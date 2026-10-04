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
import re
import json
import time
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import redis
import requests

from refraction_check import summarize_reflection
from refraction_evaluate import fetch_market, evaluate_candidate, format_scorecard
from refraction_score import has_reward_signal, short_tag
from refraction_discovery import discover
from refraction_watch import make_snapshot, save_position, watch_positions

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
# Separate, lower, EARLIER tier from the gate above -- applied before any
# expensive checks run at all, so a $50-liquidity dead pool doesn't get
# the same full pipeline (interface match, holder concentration, GoPlus,
# honeypot.is) as a genuinely liquid one. Pure noise below this gets
# skipped entirely, not even logged as a near-miss.
NOISE_LIQUIDITY_USD = float(os.environ.get("REFRACTION_NOISE_LIQUIDITY_USD", "1000"))
REQUIRE_ZERO_TAX = os.environ.get("REFRACTION_REQUIRE_ZERO_TAX", "1") not in ("0", "false", "False", "")
REQUIRE_HONEYPOT_SAFE = os.environ.get("REFRACTION_REQUIRE_HONEYPOT_SAFE", "1") not in ("0", "false", "False", "")
REQUIRE_HONEYPOT_IS_SAFE = os.environ.get("REFRACTION_REQUIRE_HONEYPOT_IS_SAFE", "1") not in ("0", "false", "False", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "120"))

DEXSCREENER_PROFILES_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
DEXSCREENER_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/base/{}"

r = redis.from_url(REDIS_URL, decode_responses=True)

SEEN_TTL = 60 * 60 * 24 * 7  # 7 days
DAILY_COUNT_KEY = "refraction:daily_count"

LOG_LIST_KEY = "refraction:log"          # profile-stream passes + near-misses, read by !rlog
MOVERS_LOG_LIST_KEY = "refraction:movers_log"  # movers-scan passes + near-misses, read by !mlog
SEARCH_LOG_LIST_KEY = "refraction:search_log"  # discovery-scan (keyword/established/trending), read by !dlog
LAST_DISCOVERY_KEY = "refraction:last_discovery_scan_at"
DISCOVERY_INTERVAL_SECONDS = int(os.environ.get("REFRACTION_DISCOVERY_INTERVAL_SECONDS", str(24 * 3600)))
DISCOVERY_MAX_CANDIDATES = int(os.environ.get("REFRACTION_DISCOVERY_MAX_CANDIDATES", "60"))
LAST_WATCH_KEY = "refraction:last_watch_at"
WATCH_INTERVAL_SECONDS = int(os.environ.get("REFRACTION_WATCH_INTERVAL_SECONDS", "900"))
LOG_LIST_MAX = 200
LAST_DIGEST_KEY = "refraction:last_digest_at"
CIRCUIT_BREAKER_KEY = "refraction:circuit_breaker"  # JSON: {tripped, reason, token, timestamp} or absent
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


def _chunk_for_discord(content: str, limit: int = 1900) -> list:
    """Discord rejects any message over 2000 characters with a 400 -- which
    this code used to ignore, silently losing the alert. Split on line
    boundaries instead."""
    chunks, cur, size = [], [], 0
    for line in content.split("\n"):
        while len(line) > limit:  # a single oversized line
            if cur:
                chunks.append("\n".join(cur)); cur, size = [], 0
            chunks.append(line[:limit]); line = line[limit:]
        if size + len(line) + 1 > limit and cur:
            chunks.append("\n".join(cur)); cur, size = [], 0
        cur.append(line); size += len(line) + 1
    if cur:
        chunks.append("\n".join(cur))
    return chunks or [""]


def notify_discord(content: str):
    if not DISCORD_WEBHOOK_URL:
        log.warning("DISCORD_WEBHOOK_URL not set, skipping alert: %s", content)
        return
    for chunk in _chunk_for_discord(content):
        try:
            resp = requests.post(DISCORD_WEBHOOK_URL, json={"content": chunk}, timeout=10)
            if resp.status_code >= 300:
                log.error("Discord webhook returned %s: %s", resp.status_code, resp.text[:200])
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


def get_pool_info(token_address: str) -> dict:
    """Kept for the callers below; the real work lives in
    refraction_evaluate.fetch_market (liquidity, pool address, buys/sells,
    plus volume, market cap, FDV and pair age used for scoring)."""
    return fetch_market(token_address)


# Minimum buy sample before treating a zero-sells count as meaningful
# rather than just low activity noise -- same reasoning and same number
# as the source this was ported from.
MIN_BUY_SAMPLE_FOR_HONEYPOT_SIGNAL = int(os.environ.get("REFRACTION_MIN_BUY_SAMPLE", "5"))


def _resolve_token_address(pool: dict, included: list):
    """
    Correct approach (ported from a working implementation that hit this
    exact bug first): resolve the base token's real address via the
    `included` array, not by string-splitting the relationship's `id`
    field. That id-splitting approach is what produced the truncated
    "0x21C82597..." address seen earlier -- this reads the token's actual
    attributes.address instead, which is what the id was never guaranteed
    to cleanly contain in the first place.

    Also requires include=base_token,quote_token on the request -- without
    it, GeckoTerminal doesn't return the `included` array at all, and this
    silently returns nothing for every pool.
    """
    base_token_id = (pool.get("relationships") or {}).get("base_token", {}).get("data", {}).get("id")
    if not base_token_id:
        return None
    match = next((t for t in included if t.get("id") == base_token_id), None)
    return (match or {}).get("attributes", {}).get("address")


def fetch_base_top_movers(limit=30, pages=3):
    """Pull several pages of Base pools ranked by 24h volume (Gecko's
    only documented sort options), then rank the combined set by 1h
    price change client-side -- there's no direct 'sort by h1 change'
    parameter. Filters out anything below MIN_LIQUIDITY_USD before
    ranking, so obvious low-liquidity wick noise doesn't waste RPC/API
    calls downstream."""
    candidates = []
    for page in range(1, pages + 1):
        try:
            resp = requests.get(GECKOTERMINAL_POOLS_URL, params={
                "sort": "h24_volume_usd_desc",
                "page": page,
                "include": "base_token,quote_token",
            }, timeout=15)
            resp.raise_for_status()
            payload = resp.json()
            data = payload.get("data", [])
            included = payload.get("included", [])
        except Exception as e:
            log.error("GeckoTerminal pools fetch failed (page %s): %s", page, e)
            continue

        for item in data:
            attrs = item.get("attributes", {}) or {}
            change_h1 = (attrs.get("price_change_percentage") or {}).get("h1")
            liquidity = attrs.get("reserve_in_usd")
            token_address = _resolve_token_address(item, included)

            if token_address and not re.fullmatch(r"0x[0-9a-fA-F]{40}", token_address):
                log.warning("Skipping malformed token address from GeckoTerminal: %r", token_address)
                token_address = None

            if change_h1 is None or token_address is None:
                continue
            try:
                if liquidity is not None and float(liquidity) < NOISE_LIQUIDITY_USD:
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
        process_candidate(m["token_address"], source="mover")


def _log_key_for(source: str) -> str:
    return {"mover": MOVERS_LOG_LIST_KEY, "search": SEARCH_LOG_LIST_KEY}.get(source, LOG_LIST_KEY)


def log_candidate(token_address: str, ev: dict, status: str, source: str = "profile"):
    """status is 'pass' or 'near_miss'. source is 'profile' (new-token
    stream), 'mover' (top-movers scan) or 'search' (discovery scan) --
    determines which Redis list this goes to, so !rlog / !mlog / !dlog show
    genuinely separate views."""
    result, sc, pool = ev["result"], ev["score"], ev["pool"]
    holders = result["detail"]["holders"]
    reward = result["detail"]["reward"]
    d = result["detail"]
    entry = {
        "address": token_address,
        "timestamp": time.time(),
        "status": status,
        "steps": result["steps"],
        "missing": [k for k in result["gates_active"] if not result["steps"].get(k)],
        "interface_pattern": d["interface"].get("pattern"),
        "holder_pct": holders.get("top_holder_pct") if holders.get("ok") else None,
        "reward_label": reward.get("label") if reward.get("ok") else None,
        "reward_token": reward.get("reward_token") if reward.get("ok") else None,
        "reflection_summary": summarize_reflection(result),
        "score": sc["score"], "grade": sc["grade"], "partial": sc["partial"],
        "buy_eligible": sc["buy_eligible"],
        "autonomy": (d.get("autonomy") or {}).get("level"),
        "payout_proof": (d.get("payouts") or {}).get("proof"),
        "liquidity_usd": pool.get("liquidity_usd"),
        "volume24h_usd": pool.get("volume24h_usd"),
    }
    key = _log_key_for(source)
    pipe = r.pipeline()
    pipe.rpush(key, json.dumps(entry))
    pipe.ltrim(key, -LOG_LIST_MAX, -1)
    pipe.execute()


BUY_ENABLED_KEY = "refraction:base:buy_enabled"  # absent or "1" = enabled, "0" = paused


def is_buy_enabled() -> bool:
    val = r.get(BUY_ENABLED_KEY)
    return val != "0"  # default enabled if never set


def trip_circuit_breaker(reason: str, token_address: str):
    """Disables the scanner entirely until a human reviews and clears it
    via !rresume in Discord -- deliberately not an auto-reset, since a
    failed test-sell is a strong enough signal to warrant a human
    actually looking at what happened before anything resumes."""
    payload = {
        "tripped": True,
        "reason": reason,
        "token": token_address,
        "timestamp": time.time(),
    }
    r.set(CIRCUIT_BREAKER_KEY, json.dumps(payload))
    notify_all(
        f"🛑 **CIRCUIT BREAKER TRIPPED** — refraction scanner disabled.\n"
        f"Token: `{token_address}`\nReason: {reason}\n\n"
        f"Scanning is paused until you review this and run `!rresume confirm` in Discord.",
        subject="🛑 Refraction circuit breaker tripped",
    )


def get_circuit_breaker_status():
    raw = r.get(CIRCUIT_BREAKER_KEY)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def clear_circuit_breaker():
    r.delete(CIRCUIT_BREAKER_KEY)


def maybe_send_digest():
    """Fires at most once per DIGEST_INTERVAL_SECONDS (default 12h). On
    the very first run it just records a start time rather than sending
    an immediate (empty) digest. Merges all three discovery logs, tags
    each entry with where it came from, and lists the best-scoring first."""
    last = r.get(LAST_DIGEST_KEY)
    now = time.time()
    if last is None:
        r.set(LAST_DIGEST_KEY, str(now))
        return
    last = float(last)
    if now - last < DIGEST_INTERVAL_SECONDS:
        return

    raw_entries = [(raw, "") for raw in r.lrange(LOG_LIST_KEY, 0, -1)]
    raw_entries += [(raw, " (movers)") for raw in r.lrange(MOVERS_LOG_LIST_KEY, 0, -1)]
    raw_entries += [(raw, " (discovery)") for raw in r.lrange(SEARCH_LOG_LIST_KEY, 0, -1)]
    entries = []
    for raw, src in raw_entries:
        try:
            e = json.loads(raw)
            if e["timestamp"] > last:
                e["_src"] = src
                entries.append(e)
        except Exception:
            continue

    r.set(LAST_DIGEST_KEY, str(now))

    if not entries:
        notify_all("📋 Refraction digest: no passes or near-misses since the last one.",
                    subject="Refraction digest — nothing found")
        return

    entries.sort(key=lambda e: (e["status"] == "pass", e.get("score") or 0), reverse=True)
    passes = [e for e in entries if e["status"] == "pass"]
    near_misses = [e for e in entries if e["status"] == "near_miss"]

    lines = [f"📋 **Refraction digest** — {len(passes)} pass(es), {len(near_misses)} near-miss(es)"]
    shown = 0
    for e in entries:
        if shown >= 15:
            lines.append(f"…and {len(entries) - shown} more — see `!rlog`, `!mlog`, `!dlog`.")
            break
        tag = f" [{'~' if e.get('partial') else ''}{e['score']} {e['grade']}]" if e.get("score") is not None else ""
        icon = "✅" if e["status"] == "pass" else "🔸"
        miss = f" missing: {', '.join(e['missing'])}" if e.get("missing") and e["status"] != "pass" else ""
        note = f" — {e['reflection_summary']}" if e.get("reflection_summary") else ""
        lines.append(f"{icon} `{e['address']}`{e['_src']}{tag}{miss}{note}")
        shown += 1

    notify_all("\n".join(lines), subject=f"Refraction digest — {len(passes)} pass, {len(near_misses)} near-miss")


def format_step_summary(result: dict) -> str:
    steps = result["steps"]
    active = set(result["gates_active"])
    lines = []
    for name, passed in steps.items():
        marker = "✓" if passed else "✗"
        tag = " (required)" if name in active else " (bonus)"
        lines.append(f"{marker} {name}{tag}")

    lines.append(summarize_reflection(result))

    return "\n".join(lines)


def process_candidate(token_address: str, source: str = "profile"):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", token_address or ""):
        log.warning("Skipping malformed candidate address: %r", token_address)
        return

    seen_key = f"refraction:seen:{token_address.lower()}"
    if r.exists(seen_key):
        return
    r.set(seen_key, "1", ex=SEEN_TTL)

    # Free pre-filters first (one DexScreener call): pure-noise liquidity,
    # and real buyers who never once managed to sell -- one of the
    # strongest honeypot tells there is.
    early_pool_info = fetch_market(token_address)
    if early_pool_info["liquidity_usd"] < NOISE_LIQUIDITY_USD:
        return  # pure noise, not even worth logging as a near-miss
    if early_pool_info["buys24h"] >= MIN_BUY_SAMPLE_FOR_HONEYPOT_SIGNAL and early_pool_info["sells24h"] == 0:
        log.info(
            "Skipping %s: %d buys but 0 sells in 24h -- strong honeypot signal, not spending checks on it",
            token_address, early_pool_info["buys24h"],
        )
        return

    # Staged evaluation (structure -> autonomy -> payout proof -> cheap
    # score -> fraud checks only if promising -> final score).
    ev = evaluate_candidate(token_address, pool=early_pool_info)
    result, sc = ev["result"], ev["score"]
    token_address = ev["address"]  # checksummed form from here on
    if ((result["detail"].get("payouts") or {}).get("proof")) == "unknown":
        # The RPC couldn't serve the log scan -- that's "couldn't check",
        # not "checked and clean". Don't cache it for a week.
        r.set(seen_key, "1", ex=3600)
    dex_url = f"https://dexscreener.com/base/{token_address}"
    source_tag = {"mover": " (via movers scan)", "search": " (via discovery scan)"}.get(source, "")

    if not result["passes_all"]:
        # Log only when there is a real reward-mechanism signal. The old
        # rule ("passed at least one required gate") logged every token,
        # because vault_supply_safe is trivially true for anything that
        # isn't an ERC-4626 vault.
        if has_reward_signal(result):
            log_candidate(token_address, ev, "near_miss", source=source)
        return  # no immediate alert -- near-misses surface in the digest / !rlog / !mlog / !dlog

    log.info("Refraction pass: %s (score %s)", token_address, sc["score"])
    log_candidate(token_address, ev, "pass", source=source)
    card = "\n".join(format_scorecard(ev))
    step_summary = format_step_summary(result)
    body = f"{step_summary}\n{card}\n{dex_url}"

    if not sc["buy_eligible"]:
        notify_all(
            f"🔍 Refraction pass on `{token_address}`{source_tag} — NOT buying.\n{body}"
        )
        return

    if not is_buy_enabled():
        notify_all(
            f"🔍 Refraction pass on `{token_address}`{source_tag} is buy-eligible but buying is paused "
            f"(`!rbuy base on` to resume).\n{body}"
        )
        return

    if buys_today() >= MAX_BUYS_PER_DAY:
        notify_all(
            f"🔍 Refraction pass on `{token_address}`{source_tag} is buy-eligible but the daily buy cap "
            f"({MAX_BUYS_PER_DAY}) is reached — not buying.\n{body}"
        )
        return

    # Liquidity is exactly the kind of thing worth re-verifying right
    # before real money moves, rather than trusting the earlier reading.
    pool_info = fetch_market(token_address)
    liquidity = pool_info["liquidity_usd"]
    if liquidity < MIN_LIQUIDITY_USD:
        notify_all(
            f"🔍 Refraction pass on `{token_address}`{source_tag} but liquidity just fell to ${liquidity:,.0f} "
            f"(floor ${MIN_LIQUIDITY_USD:,.0f}) — not buying.\n{body}"
        )
        return

    if execute_buy is None:
        notify_all(
            f"🔍 Refraction pass on `{token_address}`{source_tag} (liquidity ${liquidity:,.0f}) — "
            f"execute_buy not wired up yet, buy skipped.\n{body}"
        )
        return

    try:
        buy_result = asyncio.run(execute_buy(token_address, BUY_USD))
        increment_daily_count()

        # Snapshot what we bought and who held which levers, so the
        # position watcher can alert if any of it changes.
        try:
            save_position(r, make_snapshot(result, pool_info, sc, BUY_USD, source))
        except Exception as e:
            log.error("Could not save position snapshot for %s: %s", token_address, e)

        test_sell = buy_result.get("test_sell") or {}
        if test_sell.get("attempted") and test_sell.get("ok") is False:
            # The buy itself succeeded -- real funds spent, real tokens
            # received -- so this is reported distinctly from a buy
            # failure, then the breaker takes over from here.
            notify_all(
                f"⚠️ Bought `{token_address}`{source_tag} but the immediate test-sell FAILED: "
                f"{test_sell.get('reason')}\n{body}"
            )
            trip_circuit_breaker(
                f"Test-sell failed on `{token_address}` after a real buy: {test_sell.get('reason')}",
                token_address,
            )
            return

        test_sell_note = " | test-sell: confirmed sellable" if test_sell.get("ok") else ""
        notify_all(
            f"✅ Bought ${BUY_USD:.0f} of `{token_address}`{source_tag} (liquidity ${liquidity:,.0f}{test_sell_note}). "
            f"tx: {buy_result.get('tx_hash', 'n/a')}\n{body}"
        )
    except Exception as e:
        log.error("Buy failed for %s: %s", token_address, e)
        notify_all(f"⚠️ Buy failed for `{token_address}`{source_tag}: {e}")


def maybe_run_discovery_scan():
    """Keyword search + established-active pools + trending, about once a
    day. Reuses process_candidate() so the same dedup, staging and logging
    apply; results land in !dlog."""
    last = r.get(LAST_DISCOVERY_KEY)
    now = time.time()
    if last is not None and now - float(last) < DISCOVERY_INTERVAL_SECONDS:
        return
    r.set(LAST_DISCOVERY_KEY, str(now))
    found = discover(max_candidates=DISCOVERY_MAX_CANDIDATES)
    log.info("Discovery scan: %d candidate(s) from search / established / trending", len(found))
    for c in found:
        process_candidate(c["token_address"], source="search")


def maybe_watch_positions():
    last = r.get(LAST_WATCH_KEY)
    now = time.time()
    if last is not None and now - float(last) < WATCH_INTERVAL_SECONDS:
        return
    r.set(LAST_WATCH_KEY, str(now))
    watch_positions(r, fetch_market, notify_all)


def run():
    log.info("refraction_scanner starting, poll interval %ss, buy $%.0f, cap %d/day, liquidity floor $%.0f",
              POLL_INTERVAL, BUY_USD, MAX_BUYS_PER_DAY, MIN_LIQUIDITY_USD)
    while True:
        try:
            breaker = get_circuit_breaker_status()
            if breaker and breaker.get("tripped"):
                log.warning("Circuit breaker tripped (%s) -- scanning paused, run !rresume in Discord to review.", breaker.get("reason"))
            else:
                for profile in fetch_new_base_profiles():
                    process_candidate(profile["tokenAddress"])
                maybe_run_mover_scan()
                maybe_run_discovery_scan()
                maybe_send_digest()
        except Exception as e:
            log.error("Scan loop error: %s", e)
        try:
            maybe_watch_positions()  # runs even while scanning is paused: held tokens still need watching
        except Exception as e:
            log.error("Position watch error: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
