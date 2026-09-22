"""
refraction_honeypot_check.py

Honeypot and broader contract-security check via GoPlus Security's free
public API -- no key required, covers Base directly (chain_id 8453).
Endpoint confirmed against GoPlus's own docs and multiple independent
client libraries, not guessed:

    GET https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}

This is an independent, third-party layer on top of what
refraction_check.py already does with its own bytecode scanning. GoPlus
decompiles and statically analyzes the actual contract for a much
broader set of known scam patterns than the admin-selector blacklist
alone catches (hidden owners behind proxies, self-destruct, external
calls, anti-whale/slippage manipulation, trading cooldowns), plus real
honeypot simulation (can this contract actually be sold at all) and an
independent buy/sell tax reading that cross-checks the on-chain
simulation in refraction_tax_check.py.

WHY THIS IS A POST-HOC CHECK, NOT ONE OF check_refraction()'s GATES:
GoPlus's own docs note that very new tokens can come back with
incomplete data because their indexer hasn't caught up yet -- which
describes exactly the tokens this scanner finds first. Folding this into
the main gate set would risk permanently blocking brand-new tokens
before GoPlus has had a chance to index them (each candidate is only
ever checked once). Running it only after everything else has already
passed -- same placement as the tax check -- means it's evaluated on a
small number of already-promising candidates, not every scan.
"""
import os
import requests

GOPLUS_URL_TEMPLATE = "https://api.gopluslabs.io/api/v1/token_security/{}"
BASE_CHAIN_ID = "8453"

# Flags where "1" means a real, specific risk signal.
DANGER_FLAGS = [
    "is_honeypot",
    "cannot_sell_all",
    "cannot_buy",
    "transfer_pausable",
    "is_blacklisted",
    "hidden_owner",
    "can_take_back_ownership",
    "owner_change_balance",
    "selfdestruct",
    "trading_cooldown",
    "anti_whale_modifiable",
    "slippage_modifiable",
    "personal_slippage_modifiable",
]


def check_honeypot(token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "is_safe": bool, "flags": [tripped danger flag names],
                 "buy_tax_pct": float|None, "sell_tax_pct": float|None}
      ok=False: {"ok": False, "reason": str}
    """
    try:
        resp = requests.get(
            GOPLUS_URL_TEMPLATE.format(BASE_CHAIN_ID),
            params={"contract_addresses": token_address},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"ok": False, "reason": f"GoPlus request failed: {e}"}

    if data.get("code") != 1:
        return {"ok": False, "reason": data.get("message", "GoPlus API error")}

    result = data.get("result") or {}
    token_data = result.get(token_address.lower())
    if not token_data:
        return {"ok": False, "reason": "no data returned -- likely too new for GoPlus's indexer yet"}

    tripped = [flag for flag in DANGER_FLAGS if str(token_data.get(flag, "0")) == "1"]

    def _pct(key):
        try:
            return float(token_data.get(key)) * 100
        except (TypeError, ValueError):
            return None

    return {
        "ok": True,
        "is_safe": len(tripped) == 0,
        "flags": tripped,
        "buy_tax_pct": _pct("buy_tax"),
        "sell_tax_pct": _pct("sell_tax"),
    }
