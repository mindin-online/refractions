"""
refraction_holders.py (v4 -- top holders, classified)

WHY THIS WAS REDESIGNED. The previous version answered one question --
"is the single biggest holder a contract, holding 30-70%?" -- and that
question conflated three completely different things:

  1. a genuine separate staking/vault contract (what the check was
     originally after),
  2. the DEX liquidity itself (a contract too -- and on Uniswap v4 it is
     ONE shared singleton, the PoolManager, holding every token's
     liquidity), and
  3. a burn address (no bytecode, so it read as "not a contract" and
     failed, punishing a permanent supply burn).

Concrete evidence it was misfiring: the one real token where the old
gate passed had 33.7% held by 0x498581ff...2b2b -- which Uniswap's own
deployments page lists as the v4 PoolManager on Base. The gate was
rewarding the liquidity pool as if it were a staking contract.

WHAT THIS RETURNS NOW. The top holders, each classified:

    burn      -- known burn address (permanent, harmless)
    pool      -- an AMM pool (detected on-chain: token0()/token1() include
                 this token) or a known singleton such as Uniswap v4's
                 PoolManager. Whether pool concentration is GOOD or BAD
                 depends entirely on whether the LP is locked -- that's a
                 separate check (LP lock/burn in the GoPlus module), so
                 this file deliberately does not judge it.
    contract  -- any other contract: candidate staking/vault/vesting/
                 locker. refraction_check.py scans these for a reward
                 mechanism instead of assuming what they are.
    wallet    -- an ordinary externally-owned account.

HOW BALANCES ARE READ. Transfer logs over a bounded recent window are
used ONLY to discover candidate holder addresses. Their actual balances
are then read live with balanceOf(). The old version trusted the
log-reconstructed balances, which is wrong for reflection tokens (their
balances grow with NO Transfer event -- exactly the tokens being hunted)
and for any token older than the scan window.

KNOWN LIMITATION, stated plainly: candidates come from the recent
window, so a large holder that hasn't moved in ~a day can be missed on an
older token. Fine for fresh launches; for established tokens a holder
list from an indexer (e.g. GoPlus's `holders`) is the better source.
"""
import os
from web3 import Web3

BLOCK_WINDOW = int(os.environ.get("HOLDER_SCAN_BLOCK_WINDOW", "50000"))
CHUNK_SIZE = int(os.environ.get("HOLDER_SCAN_CHUNK_SIZE", "2000"))
MAX_LOGS = int(os.environ.get("HOLDER_SCAN_MAX_LOGS", "20000"))
CANDIDATES_TO_READ = int(os.environ.get("REFRACTION_HOLDER_CANDIDATES", "15"))
TOP_N = int(os.environ.get("REFRACTION_HOLDER_TOP_N", "6"))

TRANSFER_TOPIC = "0x" + bytes(Web3.keccak(text="Transfer(address,address,uint256)")).hex()
TOKEN0_DATA = bytes(Web3.keccak(text="token0()"))[:4]
TOKEN1_DATA = bytes(Web3.keccak(text="token1()"))[:4]

ERC20_ABI = [
    {"inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]

ZERO_ADDRESS = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")

BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# Singletons that hold pool liquidity for MANY tokens at once. Uniswap v4
# (verified against Uniswap's own deployments page, Base = chain 8453):
KNOWN_POOL_SINGLETONS = {
    "0x498581ff718922c3f8e6a244956af099b2652b2b": "Uniswap v4 PoolManager (Base)",
}
for _extra in os.environ.get("REFRACTION_EXTRA_POOL_ADDRESSES", "").split(","):
    _extra = _extra.strip().lower()
    if _extra:
        KNOWN_POOL_SINGLETONS[_extra] = "configured pool address"


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
            return logs, False, any_chunk_succeeded
        start = end + 1
    return logs, True, any_chunk_succeeded


def _read_address(w3, to: str, data: bytes):
    result = w3.eth.call({"to": to, "data": data})
    if len(result) >= 32:
        return Web3.to_checksum_address("0x" + bytes(result)[-20:].hex())
    return None


def _looks_like_amm_pool(w3, address: str, token_address: str) -> bool:
    """Uniswap v2/v3 and Aerodrome pools expose token0()/token1(). If this
    holder is a pool and one side is our token, it's the liquidity."""
    try:
        t0 = _read_address(w3, address, TOKEN0_DATA)
        t1 = _read_address(w3, address, TOKEN1_DATA)
    except Exception:
        return False
    if not t0 or not t1:
        return False
    return token_address.lower() in (t0.lower(), t1.lower())


def classify_holder(w3, address: str, token_address: str) -> dict:
    """Returns {"kind": burn|pool|contract|wallet|unknown, "label": str|None}."""
    low = address.lower()
    if low in BURN_ADDRESSES:
        return {"kind": "burn", "label": "burn address"}
    if low in KNOWN_POOL_SINGLETONS:
        return {"kind": "pool", "label": KNOWN_POOL_SINGLETONS[low]}
    try:
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
    except Exception:
        return {"kind": "unknown", "label": "could not read code"}
    if len(code) == 0:
        return {"kind": "wallet", "label": None}
    # EIP-7702: an ordinary wallet that has delegated to a contract shows
    # 0xef0100 + a 20-byte address (23 bytes). It's still a wallet.
    if len(code) == 23 and code[:3] == b"\xef\x01\x00":
        return {"kind": "wallet", "label": "EIP-7702 delegated wallet"}
    if _looks_like_amm_pool(w3, address, token_address):
        return {"kind": "pool", "label": "AMM pool"}
    return {"kind": "contract", "label": None}


def get_holder_concentration(w3, token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True,
                 "holders": [{"address", "pct", "kind", "label"}, ...],  # top N by REAL balance
                 "top_holder_address", "top_holder_is_contract", "top_holder_pct",  # kept for callers
                 "approximate": bool}
      ok=False: {"ok": False, "reason": str}
    """
    target = Web3.to_checksum_address(token_address)

    try:
        token = w3.eth.contract(address=target, abi=ERC20_ABI)
        total_supply = token.functions.totalSupply().call()
    except Exception as e:
        return {"ok": False, "reason": f"totalSupply call failed: {e}"}
    if total_supply <= 0:
        return {"ok": False, "reason": "total supply is zero"}

    logs, complete, any_chunk_succeeded = _fetch_transfer_logs(w3, target)
    if not logs:
        if not any_chunk_succeeded:
            return {"ok": False, "reason": "could not fetch transfer logs from RPC (all chunk requests failed -- check RPC_URL / rate limits)"}
        return {"ok": False, "reason": "no Transfer events found in scan window"}

    # Logs only DISCOVER candidates (rough net flow), they don't decide balances.
    flow = {}
    for log in logs:
        try:
            from_addr = Web3.to_checksum_address("0x" + bytes(log["topics"][1])[-20:].hex())
            to_addr = Web3.to_checksum_address("0x" + bytes(log["topics"][2])[-20:].hex())
            amount = int.from_bytes(bytes(log["data"]), "big")
        except Exception:
            continue
        if from_addr != ZERO_ADDRESS:
            flow[from_addr] = flow.get(from_addr, 0) - amount
        if to_addr != ZERO_ADDRESS:
            flow[to_addr] = flow.get(to_addr, 0) + amount

    ranked = sorted(flow.items(), key=lambda kv: kv[1], reverse=True)
    candidates = [addr for addr, net in ranked if net > 0][:CANDIDATES_TO_READ]
    for known in KNOWN_POOL_SINGLETONS:  # always look at the shared liquidity holders
        cs = Web3.to_checksum_address(known)
        if cs not in candidates and cs in flow:
            candidates.append(cs)
    for burn in BURN_ADDRESSES:
        cs = Web3.to_checksum_address(burn)
        if cs not in candidates and cs in flow:
            candidates.append(cs)
    if not candidates:
        return {"ok": False, "reason": "no candidate holders found in scan window"}

    # Real, current balances -- correct for reflection tokens too.
    real = []
    for addr in candidates:
        try:
            bal = token.functions.balanceOf(addr).call()
        except Exception:
            continue
        if bal > 0:
            real.append((addr, bal))
    if not real:
        return {"ok": False, "reason": "could not read any candidate balances"}
    real.sort(key=lambda kv: kv[1], reverse=True)

    holders = []
    for addr, bal in real[:TOP_N]:
        info = classify_holder(w3, addr, target)
        holders.append({
            "address": addr,
            "pct": (bal / total_supply) * 100,
            "kind": info["kind"],
            "label": info["label"],
        })

    top = holders[0]
    return {
        "ok": True,
        "holders": holders,
        "top_holder_address": top["address"],
        "top_holder_is_contract": top["kind"] in ("contract", "pool"),
        "top_holder_pct": top["pct"],
        "approximate": not complete,
    }
