"""
refraction_holders.py

Top-holder concentration check via GoldRush (Covalent) API. Requires a
GoldRush API key on their ~$10/mo tier or above -- much cheaper than
Etherscan's equivalent endpoint, which needs their $199/mo Standard plan.

GoldRush's token_holders_v2 response doesn't classify holder addresses as
contract vs EOA, so this does one extra (free) RPC call -- eth_getCode --
on whichever address turns out to hold the most, to answer that part.

Page size is fixed at 100 by the API (their only two supported values are
100 and 1000); for a freshly-launched token this is very likely the
complete holder list. The code takes the max balance across whatever
comes back rather than trusting item order, so it's correct even if the
API's sort order isn't strictly descending by balance.

Note: Covalent's v1 API has historically wrapped responses in a top-level
{"data": {...}, "error": ...} envelope, but the current OpenAPI doc for
this specific endpoint documents the payload without that wrapper. The
parsing below handles either shape defensively -- if you see "no holder
data returned" on a token you know has holders, print the raw response
once to check which shape you're actually getting back.
"""
import os
import requests
from web3 import Web3

GOLDRUSH_API_KEY = os.environ.get("GOLDRUSH_API_KEY", "")
GOLDRUSH_URL_TEMPLATE = "https://api.covalenthq.com/v1/base-mainnet/tokens/{}/token_holders_v2/"


def get_holder_concentration(w3: Web3, token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "top_holder_address": str,
                 "top_holder_is_contract": bool, "top_holder_pct": float}
      ok=False: {"ok": False, "reason": str}
    """
    if not GOLDRUSH_API_KEY:
        return {"ok": False, "reason": "GOLDRUSH_API_KEY not set"}

    target = Web3.to_checksum_address(token_address)

    try:
        resp = requests.get(
            GOLDRUSH_URL_TEMPLATE.format(target),
            params={"key": GOLDRUSH_API_KEY, "page-size": 100, "page-number": 0},
            timeout=20,
        )
        if not resp.ok:
            return {"ok": False, "reason": f"token_holders_v2 HTTP {resp.status_code}: {resp.text[:300]}"}
        raw = resp.json()
    except Exception as e:
        return {"ok": False, "reason": f"token_holders_v2 request failed: {e}"}

    if raw.get("error"):
        return {"ok": False, "reason": raw.get("error_message", "GoldRush API error")}

    payload = raw.get("data", raw)  # handle wrapped or unwrapped response shape
    items = payload.get("items") or []
    if not items:
        return {"ok": False, "reason": "no holder data returned"}

    try:
        top = max(items, key=lambda i: int(i["balance"]))
        total_supply = int(top["total_supply"])
        top_balance = int(top["balance"])
    except (KeyError, ValueError, TypeError) as e:
        return {"ok": False, "reason": f"unexpected response shape: {e}"}

    if total_supply <= 0:
        return {"ok": False, "reason": "total supply is zero"}

    pct = (top_balance / total_supply) * 100
    top_address = Web3.to_checksum_address(top["address"])

    try:
        is_contract = len(w3.eth.get_code(top_address)) > 0
    except Exception as e:
        return {"ok": False, "reason": f"eth_getCode failed for top holder: {e}"}

    return {
        "ok": True,
        "top_holder_address": top_address,
        "top_holder_is_contract": is_contract,
        "top_holder_pct": pct,
    }
