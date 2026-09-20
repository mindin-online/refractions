"""
refraction_holders.py (v3 — free, on-chain approximation)

Top-holder concentration check via Transfer-event log reconstruction --
no third-party API, no billing account to get suspended or rate-limited.
This works well specifically because these are freshly-launched tokens
(pulled from DexScreener's newest-profiles feed): total Transfer history
is small enough to scan directly over a bounded recent block window,
using the same free Base RPC everything else already uses.

Scans eth_getLogs for the token's Transfer events across the last
HOLDER_SCAN_BLOCK_WINDOW blocks (default 50,000 -- roughly a day and a
half at Base's ~2s block time), chunked to stay within public RPC log
range limits, and reconstructs approximate balances by tallying
transfers in/out. This is bounded by the scan window -- if a token is
older than the window or has unusually heavy transfer volume, the
result comes back flagged "approximate" rather than silently guessed at.

Same function signature and return contract as the previous
provider-based versions, so this is a drop-in replacement -- no changes
needed in refraction_check.py.
"""
import os
from web3 import Web3

BLOCK_WINDOW = int(os.environ.get("HOLDER_SCAN_BLOCK_WINDOW", "50000"))
CHUNK_SIZE = int(os.environ.get("HOLDER_SCAN_CHUNK_SIZE", "2000"))
MAX_LOGS = int(os.environ.get("HOLDER_SCAN_MAX_LOGS", "20000"))  # safety cap

TRANSFER_TOPIC = "0x" + bytes(Web3.keccak(text="Transfer(address,address,uint256)")).hex()

ERC20_MINIMAL_ABI = [
    {"inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]

ZERO_ADDRESS = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")


def _fetch_transfer_logs(w3, token_address: str):
    latest = w3.eth.block_number
    from_block = max(0, latest - BLOCK_WINDOW)
    logs = []
    any_chunk_succeeded = False
    start = from_block
    while start <= latest:
        end = min(start + CHUNK_SIZE - 1, latest)
        try:
            chunk_logs = w3.eth.get_logs({
                "address": token_address,
                "topics": [TRANSFER_TOPIC],
                "fromBlock": start,
                "toBlock": end,
            })
            logs.extend(chunk_logs)
            any_chunk_succeeded = True
        except Exception:
            pass  # skip chunk on RPC error (range limits, timeouts) -- best-effort
        if len(logs) > MAX_LOGS:
            return logs, False, any_chunk_succeeded  # too much volume, bail -- incomplete
        start = end + 1
    return logs, True, any_chunk_succeeded


def get_holder_concentration(w3, token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "top_holder_address": str,
                 "top_holder_is_contract": bool, "top_holder_pct": float,
                 "approximate": bool}  # True if the scan window was hit
                                        # before covering full history
      ok=False: {"ok": False, "reason": str}
    """
    target = Web3.to_checksum_address(token_address)

    try:
        contract = w3.eth.contract(address=target, abi=ERC20_MINIMAL_ABI)
        total_supply_raw = contract.functions.totalSupply().call()
    except Exception as e:
        return {"ok": False, "reason": f"totalSupply call failed: {e}"}

    if total_supply_raw <= 0:
        return {"ok": False, "reason": "total supply is zero"}

    logs, complete, any_chunk_succeeded = _fetch_transfer_logs(w3, target)

    if not logs:
        if not any_chunk_succeeded:
            return {"ok": False, "reason": "could not fetch transfer logs from RPC (all chunk requests failed -- check RPC_URL / rate limits)"}
        return {"ok": False, "reason": "no Transfer events found in scan window"}

    balances = {}
    for log in logs:
        try:
            from_addr = Web3.to_checksum_address("0x" + bytes(log["topics"][1])[-20:].hex())
            to_addr = Web3.to_checksum_address("0x" + bytes(log["topics"][2])[-20:].hex())
            amount = int.from_bytes(bytes(log["data"]), "big")
        except Exception:
            continue
        if from_addr != ZERO_ADDRESS:
            balances[from_addr] = balances.get(from_addr, 0) - amount
        if to_addr != ZERO_ADDRESS:
            balances[to_addr] = balances.get(to_addr, 0) + amount

    if not balances:
        return {"ok": False, "reason": "could not reconstruct any balances from logs"}

    top_address, top_balance = max(balances.items(), key=lambda kv: kv[1])
    if top_balance <= 0:
        return {"ok": False, "reason": "reconstructed top balance is zero or negative -- scan window likely incomplete"}

    pct = (top_balance / total_supply_raw) * 100

    try:
        is_contract = len(w3.eth.get_code(top_address)) > 0
    except Exception as e:
        return {"ok": False, "reason": f"eth_getCode failed for top holder: {e}"}

    return {
        "ok": True,
        "top_holder_address": top_address,
        "top_holder_is_contract": is_contract,
        "top_holder_pct": pct,
        "approximate": not complete,
    }
