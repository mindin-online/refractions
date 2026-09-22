"""
refraction_honeypot_is_check.py

Second, INDEPENDENT honeypot check via honeypot.is -- deliberately
separate from refraction_honeypot_check.py's GoPlus check rather than
folded into it, so a failure or blind spot in one service can't
silently take out the other. No API key required (confirmed live
against Base/chainID 8453 by the implementation this was ported from).

What makes this meaningfully different from GoPlus: this service
actually SIMULATES a real buy followed by a real sell against a forked
copy of live chain state (a real eth_call trace through the token's
actual transfer logic), rather than reading static contract flags.
That's the closest thing to a genuine "test sell before buying" that's
possible -- you can't literally sell a token you don't own yet, but
this exercises the same code path a real sell would hit, before any
real money moves. Some honeypots have asymmetric buy/sell logic (fine
to buy, reverts or 100% taxes only on sell) that a static-flag checker
can miss entirely -- this is exactly the failure mode this check
targets, and exactly what refraction_honeypot_check.py's GoPlus-based
check (static analysis, no simulation) cannot catch on its own.

Docs: https://docs.honeypot.is/ishoneypot
"""
import os
import requests

HONEYPOT_IS_URL = "https://api.honeypot.is/v2/IsHoneypot"
BASE_CHAIN_ID = 8453

# riskLevel is 0-100. Per honeypot.is's own docs: low = 1-19, medium =
# 20-59, high = 60-79, very_high = 80-89, honeypot = 90-100. Blocking at
# "medium" and above (not just "high") is a deliberately conservative
# choice ported as-is -- this will reject some real, fine tokens that
# just look unusual, an accepted tradeoff for a bot that isn't watched
# in real time.
MAX_RISK_LEVEL = int(os.environ.get("REFRACTION_MAX_HONEYPOT_IS_RISK", "19"))

# honeypot.is returns tax as a plain percent (e.g. 5 = 5%), NOT a 0-1
# fraction like GoPlus -- do not reuse the GoPlus module's threshold
# constants against these values.
MAX_TAX_PCT = float(os.environ.get("REFRACTION_MAX_HONEYPOT_IS_TAX_PCT", "30"))


def check_honeypot_is(token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "is_safe": bool, "reason": str}
      ok=False: {"ok": False, "reason": str}

    Same two-level shape as refraction_honeypot_check.py: "ok" means a
    usable answer came back at all; unverifiable fails closed (is_safe
    False) rather than being treated as a free pass, same philosophy as
    the GoPlus check.
    """
    def unsafe(reason):
        return {"ok": True, "is_safe": False, "reason": reason}

    try:
        resp = requests.get(
            HONEYPOT_IS_URL,
            params={"address": token_address, "chainID": BASE_CHAIN_ID},
            headers={"Accept": "application/json"},
            timeout=15,
        )
    except Exception as e:
        return {"ok": False, "reason": f"honeypot.is check errored ({e})"}

    if resp.status_code == 404:
        return unsafe("honeypot.is has no pool data for this token yet -- too new to run a buy+sell simulation, blocking.")
    if not resp.ok:
        return unsafe(f"honeypot.is API returned {resp.status_code} -- can't verify, blocking buy.")

    try:
        data = resp.json()
    except Exception as e:
        return {"ok": False, "reason": f"honeypot.is returned unparseable data: {e}"}

    if data.get("simulationSuccess") is False:
        err = (data.get("simulationError") or "reason not given")
        return unsafe(f"honeypot.is couldn't simulate a buy+sell for this token ({err}) -- can't confirm it's actually sellable, blocking.")

    honeypot_result = data.get("honeypotResult") or {}
    if honeypot_result.get("isHoneypot"):
        reason = honeypot_result.get("honeypotReason", "reason not given")
        return unsafe(f"honeypot.is's live buy+sell simulation flags this as a honeypot: {reason}.")

    summary = data.get("summary") or {}
    risk_level = summary.get("riskLevel")
    if isinstance(risk_level, (int, float)) and risk_level > MAX_RISK_LEVEL:
        return unsafe(f"honeypot.is rates this \"{summary.get('risk')}\" risk ({risk_level}/100, threshold {MAX_RISK_LEVEL}) -- blocking.")

    sim = data.get("simulationResult") or {}
    buy_tax = float(sim.get("buyTax") or 0)
    sell_tax = float(sim.get("sellTax") or 0)
    transfer_tax = float(sim.get("transferTax") or 0)
    if buy_tax > MAX_TAX_PCT:
        return unsafe(f"honeypot.is simulated a {buy_tax}% buy tax -- too high.")
    if sell_tax > MAX_TAX_PCT:
        return unsafe(f"honeypot.is simulated a {sell_tax}% sell tax -- too high.")
    if transfer_tax > MAX_TAX_PCT:
        return unsafe(f"honeypot.is simulated a {transfer_tax}% transfer tax -- too high.")

    return {"ok": True, "is_safe": True, "reason": f"Passed honeypot.is live buy+sell simulation (risk: {summary.get('risk', 'unknown')})."}
