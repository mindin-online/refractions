"""
refraction_scanner.py

Railway worker service. Polls DexScreener's newest-token-profile feed for
Base chain tokens, runs each new contract through the full refraction
pipeline (refraction_check.check_refraction -- interface match, holder
concentration, reward token, optional Aerodrome gauge check), and
auto-buys on a pass via base_buy.py's swap logic. Buy/skip events post to
Discord via webhook. Mirrors the polling structure of poller.py
(price-alerts): timed loop + Redis dedup, no framework.

Env vars specific to this file:
  REDIS_URL                      Redis connection string (required)
  DISCORD_WEBHOOK_URL            Webhook for alerts (optional but recommended)
  REFRACTION_BUY_USD             Notional buy size in USD (default 10)
  REFRACTION_MAX_BUYS_PER_DAY    Daily buy cap, resets at UTC midnight (default 3)
  REFRACTION_MIN_LIQUIDITY_USD   Skip buy below this pool liquidity (default 5000)
  POLL_INTERVAL_SECONDS          Scan cadence (default 120, matches poller.py)

See refraction_check.py for the REFRACTION_REQUIRE_* / REFRACTION_*_PCT
env vars that control which pipeline steps gate a buy.

Requires base_buy.py to expose a callable (not just CLI-guarded) function:

    def execute_buy(token_address: str, usd_amount: float) -> dict:
        # ...your existing account.swap(AccountSwapOptions(...)) logic...
        return {"tx_hash": "0x...", "status": "..."}

If that import fails, the scanner still runs and alerts on passes, it
just skips the buy step and says so in the Discord message.
"""
import os
import time
import logging
from datetime import datetime, timedelta, timezone

import redis
import requests

from refraction_check import check_refraction

try:
    from base_buy import execute_buy
except ImportError:
    execute_buy = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("refraction_scanner")

REDIS_URL = os.environ["REDIS_URL"]
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")
BUY_USD = float(os.environ.get("REFRACTION_BUY_USD", "10"))
MAX_BUYS_PER_DAY = int(os.environ.get("REFRACTION_MAX_BUYS_PER_DAY", "3"))
MIN_LIQUIDITY_USD = float(os.environ.get("REFRACTION_MIN_LIQUIDITY_USD", "5000"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "120"))

DEXSCREENER_PROFILES_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREENER_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/base/{}"

r = redis.from_url(REDIS_URL, decode_responses=True)

SEEN_TTL = 60 * 60 * 24 * 7  # 7 days
DAILY_COUNT_KEY = "refraction:daily_count"


def seconds_until_utc_midnight() -> int:
    now = datetime.now(timezone.utc)
    nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((nxt - now).total_seconds())


def buys_today() -> int:
    val = r.get(DAILY_COUNT_KEY)
    return int(val) if val else 0


def increment_daily_count():
    is_new = not r.exists(DAILY_COUNT_KEY)
    pipe = r.pipeline()
    pipe.incr(DAILY_COUNT_KEY)
    if is_new:
        pipe.expire(DAILY_COUNT_KEY, seconds_until_utc_midnight())
    pipe.execute()


def notify_discord(content: str):
    if not DISCORD_WEBHOOK_URL:
        log.warning("DISCORD_WEBHOOK_URL not set, skipping alert: %s", content)
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": content}, timeout=10)
    except Exception as e:
        log.error("Discord webhook failed: %s", e)


def fetch_new_base_profiles():
    resp = requests.get(DEXSCREENER_PROFILES_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return [p for p in data if p.get("chainId") == "base" and p.get("tokenAddress")]


def get_liquidity_usd(token_address: str) -> float:
    try:
        resp = requests.get(DEXSCREENER_PAIRS_URL.format(token_address), timeout=15)
        resp.raise_for_status()
        pairs = resp.json()
        if not pairs:
            return 0.0
        return max((p.get("liquidity", {}).get("usd", 0) or 0) for p in pairs)
    except Exception as e:
        log.error("Liquidity lookup failed for %s: %s", token_address, e)
        return 0.0


def format_step_summary(result: dict) -> str:
    steps = result["steps"]
    active = set(result["gates_active"])
    lines = []
    for name, passed in steps.items():
        marker = "✓" if passed else "✗"
        tag = " (required)" if name in active else " (bonus)"
        lines.append(f"{marker} {name}{tag}")
    return "\n".join(lines)


def process_candidate(token_address: str):
    seen_key = f"refraction:seen:{token_address.lower()}"
    if r.exists(seen_key):
        return
    r.set(seen_key, "1", ex=SEEN_TTL)

    result = check_refraction(token_address)
    dex_url = f"https://dexscreener.com/base/{token_address}"

    if not result["passes_all"]:
        return  # silent skip -- only alert on passes or on passes-but-blocked-by-cap/liquidity

    log.info("Refraction pass: %s", token_address)
    step_summary = format_step_summary(result)

    if buys_today() >= MAX_BUYS_PER_DAY:
        notify_discord(
            f"🔍 Refraction pass on `{token_address}` but daily buy cap ({MAX_BUYS_PER_DAY}) "
            f"reached — not buying.\n{step_summary}\n{dex_url}"
        )
        return

    liquidity = get_liquidity_usd(token_address)
    if liquidity < MIN_LIQUIDITY_USD:
        notify_discord(
            f"🔍 Refraction pass on `{token_address}` but liquidity (${liquidity:,.0f}) "
            f"below floor (${MIN_LIQUIDITY_USD:,.0f}) — not buying.\n{step_summary}\n{dex_url}"
        )
        return

    if execute_buy is None:
        notify_discord(
            f"🔍 Refraction pass on `{token_address}` (liquidity ${liquidity:,.0f}) — "
            f"execute_buy not wired up yet, buy skipped.\n{step_summary}\n{dex_url}"
        )
        return

    try:
        buy_result = execute_buy(token_address, BUY_USD)
        increment_daily_count()
        notify_discord(
            f"✅ Bought ${BUY_USD:.0f} of `{token_address}` (liquidity ${liquidity:,.0f}). "
            f"tx: {buy_result.get('tx_hash', 'n/a')}\n{step_summary}\n{dex_url}"
        )
    except Exception as e:
        log.error("Buy failed for %s: %s", token_address, e)
        notify_discord(f"⚠️ Buy failed for `{token_address}`: {e}")


def run():
    log.info("refraction_scanner starting, poll interval %ss, buy $%.0f, cap %d/day, liquidity floor $%.0f",
              POLL_INTERVAL, BUY_USD, MAX_BUYS_PER_DAY, MIN_LIQUIDITY_USD)
    while True:
        try:
            for profile in fetch_new_base_profiles():
                process_candidate(profile["tokenAddress"])
        except Exception as e:
            log.error("Scan loop error: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
