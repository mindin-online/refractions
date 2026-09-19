"""
refraction_holders.py

Top-holder concentration check via Etherscan's unified V2 API. The
`topholders` action is a Pro-plan endpoint (Standard plan and above) --
one Etherscan API key covers all 60+ chains they support, Base included
via chainid=8453, so this is the same key people colloquially call a
"Basescan Pro" key.

Conveniently, the response already classifies each holder address as
contract ("C") or externally-owned, so no separate eth_getCode call is
needed to answer "is the top holder a contract."
"""
import os
import requests
from web3 import Web3

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"
BASE_CHAIN_ID = "8453"

ERC20_MINIMAL_ABI = [
    {"inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "stateMutability": "view", "type": "function"},
]


def get_holder_concentration(w3: Web3, token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "top_holder_address": str,
                 "top_holder_is_contract": bool, "top_holder_pct": float}
      ok=False: {"ok": False, "reason": str}
    """
    if not ETHERSCAN_API_KEY:
        return {"ok": False, "reason": "ETHERSCAN_API_KEY not set"}

    target = Web3.to_checksum_address(token_address)

    try:
        resp = requests.get(ETHERSCAN_V2_URL, params={
            "chainid": BASE_CHAIN_ID,
            "module": "token",
            "action": "topholders",
            "contractaddress": target,
            "offset": 5,
            "apikey": ETHERSCAN_API_KEY,
        }, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"ok": False, "reason": f"topholders request failed: {e}"}

    if data.get("status") != "1" or not data.get("result"):
        return {"ok": False, "reason": data.get("message", "no holder data")}

    top = data["result"][0]

    try:
        contract = w3.eth.contract(address=target, abi=ERC20_MINIMAL_ABI)
        total_supply_raw = contract.functions.totalSupply().call()
        decimals = contract.functions.decimals().call()
        total_supply = total_supply_raw / (10 ** decimals)
    except Exception as e:
        return {"ok": False, "reason": f"totalSupply/decimals call failed: {e}"}

    if total_supply <= 0:
        return {"ok": False, "reason": "total supply is zero"}

    top_qty = float(top["TokenHolderQuantity"])  # already human-normalized per Etherscan's example response
    pct = (top_qty / total_supply) * 100

    return {
        "ok": True,
        "top_holder_address": top["TokenHolderAddress"],
        "top_holder_is_contract": top.get("TokenHolderAddressType") == "C",
        "top_holder_pct": pct,
    }
