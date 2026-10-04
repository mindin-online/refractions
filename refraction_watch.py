"""
refraction_watch.py

Post-buy monitoring. Every check before this point happens BEFORE a buy, but
the thing being bought can change afterward: an owner can swap the payout
token or the dividend tracker, a proxy can be upgraded, liquidity can be
pulled, payouts can quietly stop. This watches each held token and ALERTS --
it does not sell (no automated selling exists in this codebase; you decide).

At buy time a snapshot is stored in Redis (refraction:positions). Each cycle
compares live state to it:
  * owner() of every contract in scope changed
  * a proxy's implementation address changed (upgrade)
  * the token's dividendTracker() changed
  * the reward asset changed
  * liquidity fell below 50% / 20% of the level at buy
  * (every ~6h) payouts that were proven are no longer observed
Each distinct problem alerts once, then is remembered, so a standing problem
doesn't re-alert every 15 minutes.
"""
import json
import time
from web3 import Web3

import refraction_check as rc
from refraction_autonomy import EIP1967_IMPL_SLOT
from refraction_payouts import verify_payouts

POSITIONS_KEY = "refraction:positions"
PAYOUT_RECHECK_SECONDS = 6 * 3600


def _impl_of(w3, addr):
    try:
        raw = w3.eth.get_storage_at(Web3.to_checksum_address(addr), EIP1967_IMPL_SLOT)
        v = Web3.to_checksum_address("0x" + bytes(raw)[-20:].hex())
        return None if v.lower() == "0x0000000000000000000000000000000000000000" else v
    except Exception:
        return None


def _owner_live(w3, addr):
    try:
        out = w3.eth.call({"to": Web3.to_checksum_address(addr), "data": bytes(Web3.keccak(text="owner()"))[:4]})
        return Web3.to_checksum_address("0x" + bytes(out)[-20:].hex()) if len(out) >= 32 else None
    except Exception:
        return None


def make_snapshot(result: dict, pool: dict, score: dict, usd: float, source: str) -> dict:
    d = result["detail"]
    a = d.get("autonomy") or {}
    w3 = rc.w3
    contracts = []
    for c in a.get("contracts", []):
        contracts.append({"address": c["address"], "role": c["role"],
                          "owner": c["owner"]["address"], "impl": _impl_of(w3, c["address"])})
    reward = d.get("reward") or {}
    return {
        "token": result["address"], "bought_at": time.time(), "usd": usd, "source": source,
        "liquidity_usd": pool.get("liquidity_usd"), "score": score["score"], "grade": score["grade"],
        "pattern": d["interface"].get("pattern"), "autonomy": a.get("level"),
        "mechanism": (d.get("mechanism") or {}).get("address"),
        "tracker": (d.get("mechanism") or {}).get("tracker"),
        "reward_token": reward.get("reward_token"), "reward_observed": bool(reward.get("observed")),
        "payers": (d.get("payouts") or {}).get("payers", []),
        "contracts": contracts, "alerted": [], "last_payout_check": time.time(),
        "payouts_were_strong": (d.get("payouts") or {}).get("proof") == "strong",
    }


def save_position(r, snap: dict):
    r.hset(POSITIONS_KEY, snap["token"].lower(), json.dumps(snap))


def check_position(snap: dict, fetch_market) -> list:
    """Returns [(code, message)] for problems not yet alerted."""
    w3 = rc.w3
    token = snap["token"]
    problems = []

    for c in snap.get("contracts", []):
        live_owner = _owner_live(w3, c["address"])
        if live_owner and c.get("owner") and live_owner.lower() != c["owner"].lower():
            problems.append((f"owner:{c['address']}", f"owner of the {c['role']} contract changed: {c['owner']} → {live_owner}"))
        live_impl = _impl_of(w3, c["address"])
        if c.get("impl") and live_impl and live_impl.lower() != c["impl"].lower():
            problems.append((f"impl:{c['address']}", f"the {c['role']} contract was UPGRADED: {c['impl']} → {live_impl}"))

    if snap.get("tracker"):
        live_tracker = rc._read_address_accessor(token, "dividendTracker()")
        if live_tracker and live_tracker.lower() != snap["tracker"].lower():
            problems.append(("tracker", f"dividendTracker() now points to {live_tracker} (was {snap['tracker']})"))

    if snap.get("reward_token") and not snap.get("reward_observed") and snap.get("mechanism"):
        live = rc._resolve_reward([snap["mechanism"], token], token, snap.get("pattern"))
        if live.get("ok") and live["reward_token"].lower() != snap["reward_token"].lower():
            problems.append(("reward", f"reward asset changed: {snap['reward_token']} → {live['reward_token']}"))

    market = fetch_market(token)
    base_liq = snap.get("liquidity_usd") or 0
    if base_liq > 0:
        ratio = (market.get("liquidity_usd") or 0) / base_liq
        if ratio < 0.2:
            problems.append(("liq20", f"LIQUIDITY COLLAPSE: ${market['liquidity_usd']:,.0f} left ({ratio:.0%} of ${base_liq:,.0f} at buy)"))
        elif ratio < 0.5:
            problems.append(("liq50", f"liquidity down to ${market['liquidity_usd']:,.0f} ({ratio:.0%} of ${base_liq:,.0f} at buy)"))

    if snap.get("payouts_were_strong") and time.time() - snap.get("last_payout_check", 0) >= PAYOUT_RECHECK_SECONDS:
        snap["last_payout_check"] = time.time()
        assets = {snap["reward_token"]: "reward"} if snap.get("reward_token") else dict(rc.MAINSTREAM_REWARD_TOKENS)
        p = verify_payouts(w3, token, snap.get("payers") or [snap.get("mechanism") or token], assets)
        if p["proof"] == "none":
            problems.append(("payouts", "payouts were proven at buy but none are observed in the recent window"))

    fresh = [(code, msg) for code, msg in problems if code not in snap.get("alerted", [])]
    return fresh


def watch_positions(r, fetch_market, notify):
    for token, raw in (r.hgetall(POSITIONS_KEY) or {}).items():
        try:
            snap = json.loads(raw)
        except Exception:
            continue
        try:
            fresh = check_position(snap, fetch_market)
        except Exception:
            continue
        for code, msg in fresh:
            snap.setdefault("alerted", []).append(code)
            notify(f"🔴 **Position alert** `{snap['token']}` — {msg}\n(held since {time.strftime('%m/%d %H:%M UTC', time.gmtime(snap['bought_at']))}; "
                   f"this only alerts — it does not sell.)", subject="🔴 Refraction position alert")
        snap["last_checked"] = time.time()
        r.hset(POSITIONS_KEY, token, json.dumps(snap))
