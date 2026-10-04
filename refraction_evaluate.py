"""
refraction_evaluate.py

The single entry point both the live scanner and the Discord !check command
call, so they can never disagree about what a token scored.

STAGES (cost control -- the point of the staged design):
  1. check_refraction()     structural checks + autonomy + payout proof.
                            Runs on every candidate that gets past the free
                            DexScreener pre-filters. Autonomy and payout log
                            scans inside it only run when a qualifying
                            pattern was actually found.
  2. cheap score            computed from stage 1 + market data.
  3. fraud stage            tax simulation, GoPlus, honeypot.is -- paid-for
                            API calls. Runs only when the cheap score is
                            promising (REFRACTION_STAGE3_MIN_PRE_PCT of 80),
                            when the token already passed every structural
                            gate, or when forced (!check always forces it).
  4. final score + buy decision.
"""
import os
import requests
from web3 import Web3

import refraction_check as _rc
from refraction_check import check_refraction, summarize_reflection
from refraction_score import score_candidate, should_run_stage3
from refraction_honeypot_check import check_honeypot
from refraction_honeypot_is_check import check_honeypot_is
from refraction_tax_check import check_transfer_tax

DEXSCREENER_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/base/{}"

EMPTY_MARKET = {
    "liquidity_usd": 0.0, "pool_address": None, "buys24h": 0, "sells24h": 0,
    "volume24h_usd": 0.0, "market_cap_usd": None, "fdv_usd": None, "pair_age_days": None, "price_usd": None,
}


def fetch_market(token_address: str) -> dict:
    """Market data for the deepest pair, from DexScreener (free, no key).
    Superset of the old get_pool_info() -- same keys, plus volume, market
    cap, FDV and pair age for scoring."""
    try:
        resp = requests.get(DEXSCREENER_PAIRS_URL.format(token_address), timeout=15)
        resp.raise_for_status()
        pairs = resp.json()
        if not pairs:
            return dict(EMPTY_MARKET)
        best = max(pairs, key=lambda p: (p.get("liquidity", {}) or {}).get("usd", 0) or 0)
        txns = (best.get("txns", {}) or {}).get("h24", {}) or {}
        created = best.get("pairCreatedAt")
        age_days = None
        if created:
            import time
            age_days = max(0.0, (time.time() - created / 1000) / 86400)
        return {
            "liquidity_usd": (best.get("liquidity", {}) or {}).get("usd", 0) or 0,
            "pool_address": best.get("pairAddress"),
            "buys24h": int(txns.get("buys", 0) or 0),
            "sells24h": int(txns.get("sells", 0) or 0),
            "volume24h_usd": float((best.get("volume", {}) or {}).get("h24", 0) or 0),
            "market_cap_usd": best.get("marketCap"),
            "fdv_usd": best.get("fdv"),
            "pair_age_days": age_days,
            "price_usd": float(best["priceUsd"]) if best.get("priceUsd") else None,
        }
    except Exception:
        return dict(EMPTY_MARKET)


def run_stage3(token_address: str, pool: dict) -> dict:
    """All three fraud checks. Each result is {"ok": bool, ...}; an exception
    becomes ok=False (inconclusive), never a silent pass."""
    out = {}
    pool_address = pool.get("pool_address")
    try:
        out["tax"] = (check_transfer_tax(token_address, pool_address) if pool_address
                      else {"ok": False, "reason": "no pool address found for the tax simulation"})
    except Exception as e:
        out["tax"] = {"ok": False, "reason": f"tax check errored: {e}"}
    try:
        out["goplus"] = check_honeypot(token_address)
    except Exception as e:
        out["goplus"] = {"ok": False, "reason": f"GoPlus errored: {e}"}
    try:
        out["honeypot_is"] = check_honeypot_is(token_address)
    except Exception as e:
        out["honeypot_is"] = {"ok": False, "reason": f"honeypot.is errored: {e}"}
    return out


def _read_uint(to: str, sig: str):
    try:
        out = _rc.w3.eth.call({"to": Web3.to_checksum_address(to), "data": bytes(Web3.keccak(text=sig))[:4]})
        return int.from_bytes(bytes(out)[:32], "big") if len(out) >= 32 else None
    except Exception:
        return None


def check_min_balance(result: dict, pool: dict):
    """Dividend trackers only pay holders above a minimum balance
    (minimumTokenBalanceForDividends). A small buy can land under it and
    earn nothing -- so compare what REFRACTION_BUY_USD actually buys."""
    d = result["detail"]
    if d["interface"].get("pattern") != "dividend":
        return None
    mech = d.get("mechanism") or {}
    raw = None
    for addr in [mech.get("tracker"), mech.get("address"), result["address"]]:
        if addr:
            raw = _read_uint(addr, "minimumTokenBalanceForDividends()")
            if raw is not None:
                break
    price = pool.get("price_usd")
    if raw is None:
        return {"ok": False, "reason": "minimum balance not readable"}
    if not price:
        return {"ok": False, "reason": "no token price to convert the buy size"}
    dec = _read_uint(result["address"], "decimals()")
    dec = dec if dec is not None and dec <= 36 else 18
    min_tokens = raw / 10 ** dec
    buy_usd = float(os.environ.get("REFRACTION_BUY_USD", "10"))
    expected = buy_usd / price
    return {"ok": True, "min_tokens": min_tokens, "min_usd": min_tokens * price,
            "expected_tokens": expected, "qualifies": expected >= min_tokens}


def evaluate_candidate(token_address: str, pool: dict = None, force_stage3: bool = False) -> dict:
    result = check_refraction(token_address)
    token = result["address"]
    pool = pool if pool is not None else fetch_market(token)
    result["detail"]["min_balance"] = check_min_balance(result, pool)
    cheap = score_candidate(result, pool, None)
    stage3 = None
    if force_stage3 or should_run_stage3(result, cheap):
        stage3 = run_stage3(token, pool)
    sc = score_candidate(result, pool, stage3) if stage3 is not None else cheap
    return {
        "address": token, "result": result, "pool": pool, "stage3": stage3, "score": sc,
        "summary": summarize_reflection(result),
    }


def format_scorecard(ev: dict, max_blockers: int = 4) -> list:
    """Plain-text lines describing the score, shared by !check, alerts and
    the digest so the wording lives in one place."""
    from refraction_score import short_tag
    sc, res, pool = ev["score"], ev["result"], ev["pool"]
    d = res["detail"]
    lines = []
    tag = short_tag(sc)
    lines.append(f"SCORE {tag}" + ("  (partial -- fraud checks not run)" if sc["partial"] else ""))
    lines.append("  " + " | ".join(f"{k} {p}/{m}" for k, (p, m) in sc["components"].items()))

    a, p = d.get("autonomy"), d.get("payouts")
    if a:
        why = "; ".join(a["live_levers"][:3]) if a["live_levers"] else (a["reasons"][0] if a["reasons"] else "")
        lines.append(f"autonomy: {a['level']}" + (f" -- {why}" if why else ""))
    if p and p.get("ran"):
        lines.append(f"payouts: {p['proof']} -- {p['reason']}; trigger: {p['trigger']['verdict']}")

    mb = d.get("min_balance")
    if mb and mb.get("ok"):
        lines.append(f"dividend minimum: needs >= {mb['min_tokens']:,.0f} tokens (~${mb['min_usd']:,.0f}); "
                     f"the buy size gets ~{mb['expected_tokens']:,.0f} -> {'qualifies' if mb['qualifies'] else 'DOES NOT QUALIFY'}")
    market = f"market: liquidity ${pool.get('liquidity_usd') or 0:,.0f} · vol24h ${pool.get('volume24h_usd') or 0:,.0f}"
    cap = pool.get("market_cap_usd") or pool.get("fdv_usd")
    if cap:
        market += f" · mcap ${cap:,.0f}"
    lines.append(market)

    if sc["buy_eligible"]:
        lines.append("BUY-ELIGIBLE")
    else:
        bl = sc["buy_blockers"]
        lines.append("not buy-eligible: " + "; ".join(bl[:max_blockers]) + (f" (+{len(bl) - max_blockers} more)" if len(bl) > max_blockers else ""))
    return lines
