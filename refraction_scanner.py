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

Requires base_buy.py to expose an async callable:

    async def execute_buy(token_address: str, usd_amount: float) -> dict:
        ...
        return {"tx_hash": "0x...", "status": "..."}

Confirmed as of the real base_buy.py source: this is genuinely async
(uses the CDP SDK's async CdpClient), so this file calls it via
asyncio.run() from the otherwise-synchronous scan loop.
"""
import os
import json
import time
import asyncio
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

LOG_LIST_KEY = "refraction:log"          # capped list of passes + near-misses, read by !rlog too
LOG_LIST_MAX = 200
LAST_DIGEST_KEY = "refraction:last_digest_at"
DIGEST_INTERVAL_SECONDS = int(os.environ.get("REFRACTION_DIGEST_INTERVAL_SECONDS", str(12 * 3600)))

# --- periodic top-1h-movers scan (Base) ---
# DexScreener's public API has no "top movers" endpoint (checked, not
# assumed) -- GeckoTerminal's free public API does have proper pool
# ranking, so this uses that instead, purely for discovering *additional*
# candidates beyond the new-token-profile stream above. Same
# process_candidate() / same refraction pipeline either way.
GECKOTERMINAL_POOLS_URL = "https://api.geckoterminal.com/api/v2/networks/base/pools"
MOVER_SCAN_INTERVAL_SECONDS = int(os.environ.get("MOVER_SCAN_INTERVAL_SECONDS", str(4 * 3600)))
MOVER_SCAN_COUNT = int(os.environ.get("MOVER_SCAN_COUNT", "30"))
MOVER_SCAN_PAGES = int(os.environ.get("MOVER_SCAN_PAGES", "3"))
LAST_MOVER_SCAN_KEY = "refraction:last_mover_scan_at"


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


def notify_email(subject: str, body: str):
    api_key = os.environ.get("RESEND_API_KEY")
    to_addr = os.environ.get("REFRACTION_EMAIL_TO")
    if not api_key or not to_addr:
        return  # email is optional -- silently skip if not configured
    try:
        requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "from": os.environ.get("RESEND_FROM", "alerts@yourdomain.com"),
                "to": [to_addr],
                "subject": subject,
                "text": body,
            },
            timeout=10,
        )
    except Exception as e:
        log.error("Resend email failed: %s", e)


def notify_all(content: str, subject: str = "Refraction scanner — pass found"):
    """Every refraction pass goes to both channels, regardless of whether
    a buy actually happens -- so you have a record even on days you're
    out of funds, capped, or below the liquidity floor."""
    notify_discord(content)
    notify_email(subject, content)


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


def fetch_base_top_movers(limit=30, pages=3):
    """Pull several pages of Base pools ranked by 24h volume (Gecko's
    only documented sort options), then rank the combined set by 1h
    price change client-side -- there's no direct 'sort by h1 change'
    parameter. Filters out anything below MIN_LIQUIDITY_USD before
    ranking, so obvious low-liquidity wick noise doesn't waste RPC/API
    calls downstream. Verify the id-parsing below against a live
    response on first run -- written from GeckoTerminal's documented id
    format ("base_0x...") but not tested against a real payload yet."""
    candidates = []
    for page in range(1, pages + 1):
        try:
            resp = requests.get(GECKOTERMINAL_POOLS_URL, params={
                "sort": "h24_volume_usd_desc",
                "page": page,
            }, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("data", [])
        except Exception as e:
            log.error("GeckoTerminal pools fetch failed (page %s): %s", page, e)
            continue

        for item in data:
            attrs = item.get("attributes", {}) or {}
            change_h1 = (attrs.get("price_change_percentage") or {}).get("h1")
            liquidity = attrs.get("reserve_in_usd")
            base_token = ((item.get("relationships") or {}).get("base_token") or {}).get("data") or {}
            raw_id = base_token.get("id", "")
            token_address = raw_id.split("_", 1)[1] if "_" in raw_id else None

            if change_h1 is None or token_address is None:
                continue
            try:
                if liquidity is not None and float(liquidity) < MIN_LIQUIDITY_USD:
                    continue
            except (TypeError, ValueError):
                pass

            candidates.append({"token_address": token_address, "change_h1": float(change_h1)})

    candidates.sort(key=lambda c: c["change_h1"], reverse=True)
    seen_addrs, top = set(), []
    for c in candidates:
        key = c["token_address"].lower()
        if key in seen_addrs:
            continue
        seen_addrs.add(key)
        top.append(c)
        if len(top) >= limit:
            break
    return top


def maybe_run_mover_scan():
    """Fires at most once per MOVER_SCAN_INTERVAL_SECONDS (default 4h).
    Reuses process_candidate() as-is -- same Redis 'seen' dedup applies,
    so a token already checked via the profile-stream above won't be
    re-checked here, and vice versa."""
    last = r.get(LAST_MOVER_SCAN_KEY)
    now = time.time()
    if last is not None and now - float(last) < MOVER_SCAN_INTERVAL_SECONDS:
        return
    r.set(LAST_MOVER_SCAN_KEY, str(now))

    log.info("Running periodic top-movers scan (Base, top %d by 1h change)", MOVER_SCAN_COUNT)
    movers = fetch_base_top_movers(limit=MOVER_SCAN_COUNT, pages=MOVER_SCAN_PAGES)
    for m in movers:
        process_candidate(m["token_address"])


def log_candidate(token_address: str, result: dict, status: str):
    """status is 'pass' or 'near_miss'. Read back by both the twice-daily
    digest below and the !rlog Discord command (same Redis, different
    service) -- capped list so it never grows unbounded."""
    holders = result["detail"]["holders"]
    entry = {
        "address": token_address,
        "timestamp": time.time(),
        "status": status,
        "steps": result["steps"],
        "interface_pattern": result["detail"]["interface"].get("pattern"),
        "holder_pct": holders.get("top_holder_pct") if holders.get("ok") else None,
    }
    pipe = r.pipeline()
    pipe.rpush(LOG_LIST_KEY, json.dumps(entry))
    pipe.ltrim(LOG_LIST_KEY, -LOG_LIST_MAX, -1)
    pipe.execute()


def maybe_send_digest():
    """Fires at most once per DIGEST_INTERVAL_SECONDS (default 12h). On
    the very first run it just records a start time rather than sending
    an immediate (empty) digest."""
    last = r.get(LAST_DIGEST_KEY)
    now = time.time()
    if last is None:
        r.set(LAST_DIGEST_KEY, str(now))
        return
    last = float(last)
    if now - last < DIGEST_INTERVAL_SECONDS:
        return

    raw_entries = r.lrange(LOG_LIST_KEY, 0, -1)
    entries = []
    for raw in raw_entries:
        try:
            e = json.loads(raw)
            if e["timestamp"] > last:
                entries.append(e)
        except Exception:
            continue

    r.set(LAST_DIGEST_KEY, str(now))

    if not entries:
        notify_all("📋 Refraction digest: no passes or near-misses since the last one.",
                    subject="Refraction digest — nothing found")
        return

    passes = [e for e in entries if e["status"] == "pass"]
    near_misses = [e for e in entries if e["status"] == "near_miss"]

    lines = [f"📋 **Refraction digest** — {len(passes)} pass(es), {len(near_misses)} near-miss(es)"]
    for e in passes:
        lines.append(f"✅ `{e['address']}` — {e['interface_pattern'] or '?'} pattern")
    for e in near_misses:
        gates_passed = [k for k, v in e["steps"].items() if v]
        lines.append(f"🔸 `{e['address']}` — passed: {', '.join(gates_passed) or 'none'}")

    notify_all("\n".join(lines), subject=f"Refraction digest — {len(passes)} pass, {len(near_misses)} near-miss")


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
        active_gates = set(result["gates_active"])
        required_passed = sum(1 for k in active_gates if result["steps"].get(k))
        if required_passed >= 1:
            log_candidate(token_address, result, "near_miss")
        return  # no immediate alert -- near-misses surface in the twice-daily digest / !rlog instead

    log.info("Refraction pass: %s", token_address)
    log_candidate(token_address, result, "pass")
    step_summary = format_step_summary(result)

    if buys_today() >= MAX_BUYS_PER_DAY:
        notify_all(
            f"🔍 Refraction pass on `{token_address}` but daily buy cap ({MAX_BUYS_PER_DAY}) "
            f"reached — not buying.\n{step_summary}\n{dex_url}"
        )
        return

    liquidity = get_liquidity_usd(token_address)
    if liquidity < MIN_LIQUIDITY_USD:
        notify_all(
            f"🔍 Refraction pass on `{token_address}` but liquidity (${liquidity:,.0f}) "
            f"below floor (${MIN_LIQUIDITY_USD:,.0f}) — not buying.\n{step_summary}\n{dex_url}"
        )
        return

    if execute_buy is None:
        notify_all(
            f"🔍 Refraction pass on `{token_address}` (liquidity ${liquidity:,.0f}) — "
            f"execute_buy not wired up yet, buy skipped.\n{step_summary}\n{dex_url}"
        )
        return

    try:
        buy_result = asyncio.run(execute_buy(token_address, BUY_USD))
        increment_daily_count()
        notify_all(
            f"✅ Bought ${BUY_USD:.0f} of `{token_address}` (liquidity ${liquidity:,.0f}). "
            f"tx: {buy_result.get('tx_hash', 'n/a')}\n{step_summary}\n{dex_url}"
        )
    except Exception as e:
        log.error("Buy failed for %s: %s", token_address, e)
        notify_all(f"⚠️ Buy failed for `{token_address}`: {e}")


def run():
    log.info("refraction_scanner starting, poll interval %ss, buy $%.0f, cap %d/day, liquidity floor $%.0f",
              POLL_INTERVAL, BUY_USD, MAX_BUYS_PER_DAY, MIN_LIQUIDITY_USD)
    while True:
        try:
            for profile in fetch_new_base_profiles():
                process_candidate(profile["tokenAddress"])
            maybe_run_mover_scan()
            maybe_send_digest()
        except Exception as e:
            log.error("Scan loop error: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
