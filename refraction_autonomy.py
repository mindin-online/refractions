"""
refraction_autonomy.py

"Can anyone steer or stop the payout?" -- the on-chain version of the
managerial-control question.

WHY THIS EXISTS. The old no_admin_keys gate asked "does the bytecode contain
owner()/renounceOwnership()/...?". That fails every OpenZeppelin Ownable
token even after its owner has renounced (renounceOwnership() is still in
the code), so it could only ever pass tokens that never had an owner at all.
What actually matters is whether anyone STILL HOLDS the levers. So this
module reads the live state:

  1. Which payout-relevant levers exist in the code (selector scan --
     redirect the payout token or tracker, sweep reward funds, upgrade,
     pause, change fees, hand-fund rewards).
  2. Who holds control: owner() on the token, the staking/vault contract,
     and the dividend tracker -- renounced / contract / wallet / none.
  3. Who funds rewards (Synthetix-style pools only): rewardsDistribution().
     notifyRewardAmount() is, by design in that template, a manual act.
  4. Whether the contract is an upgradeable proxy.

RESULT LEVELS
  autonomous   no live lever: owners renounced (or never existed), no wallet
               funds rewards, not upgradeable.
  constrained  levers exist but their holder is a CONTRACT (could be a
               multisig/timelock -- unreadable from here) or only
               fee/config levers are live.
  managed      a wallet can redirect/sweep/upgrade/pause, or a wallet
               hand-funds rewards.
  unknown      nothing could be read.

HONEST LIMITS. Selector names are a vocabulary of the names seen in the
published templates and real contracts -- a lever under an unknown name is
invisible. A contract owner is reported as "contract", not judged: a
timelocked multisig and a throwaway contract look identical from here.
A role-based (AccessControl) contract has no owner() to read; levers on
such a contract are reported as "control model unreadable" and the level
is capped at constrained, never autonomous.
"""
from web3 import Web3

ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

EIP1967_IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bb", 16)
EIP1967_ADMIN_SLOT = int("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16)

# severity: "high" = can redirect / sweep / upgrade / halt; "medium" = can
# change economics or config; funding levers are handled separately.
LEVERS = {
    # payout redirection
    "updatePayoutToken(address)": "high",
    "setPayoutToken(address)": "high",
    "setRewardToken(address)": "high",
    "updateRewardToken(address)": "high",
    "updateDividendTracker(address)": "high",
    "setDividendTracker(address)": "high",
    "setRewardsDistribution(address)": "high",
    # sweeping funds
    "recoverERC20(address,uint256)": "high",
    "recoverForeignERC20(address,uint256)": "high",
    "withdrawToken(address)": "high",
    # code replacement
    "upgradeTo(address)": "high",
    "upgradeToAndCall(address,bytes)": "high",
    # halting / singling out
    "pause()": "high",
    "unpause()": "high",
    "blacklist(address)": "high",
    "mint(address,uint256)": "high",
    # economics / config
    "updateRewardFee(uint256)": "medium",
    "updateMarketingFee(uint256)": "medium",
    "updateLiquidityFee(uint256)": "medium",
    "excludeFromDividends(address)": "medium",
    "excludeFromFee(address)": "medium",
    "excludeFromFees(address,bool)": "medium",
    "updateClaimWait(uint256)": "medium",
    "updateGasForProcessing(uint256)": "medium",
    "setRewardsDuration(uint256)": "medium",
    "updatePeriodFinish(uint256)": "medium",
}
FUNDING_SIGNATURE = "notifyRewardAmount(uint256)"


def _sel(sig: str) -> str:
    return bytes(Web3.keccak(text=sig))[:4].hex()


def _read_address(w3, to: str, sig: str):
    try:
        out = w3.eth.call({"to": to, "data": bytes(Web3.keccak(text=sig))[:4]})
    except Exception:
        return None
    if len(out) < 32:
        return None
    return Web3.to_checksum_address("0x" + bytes(out)[-20:].hex())


def _is_contract(w3, address: str) -> bool:
    try:
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
    except Exception:
        return False
    if len(code) == 0:
        return False
    if len(code) == 23 and code[:3] == b"\xef\x01\x00":  # EIP-7702 delegated wallet
        return False
    return True


def _classify_holder(w3, address):
    """-> (state, address). state in none/renounced/contract/wallet."""
    if address is None:
        return "none", None
    low = address.lower()
    if low in (ZERO, DEAD):
        return "renounced", address
    return ("contract" if _is_contract(w3, address) else "wallet"), address


def _read_owner(w3, contract: str, bytecode_hex: str):
    if _sel("owner()") not in bytecode_hex:
        return {"state": "none", "address": None}
    try:
        out = w3.eth.call({"to": contract, "data": bytes(Web3.keccak(text="owner()"))[:4]})
        if len(out) < 32:
            return {"state": "none", "address": None}
        addr = Web3.to_checksum_address("0x" + bytes(out)[-20:].hex())
    except Exception:
        return {"state": "none", "address": None}
    state, a = _classify_holder(w3, addr)
    return {"state": state, "address": a}


def _read_proxy(w3, address: str):
    """-> {"upgradeable": bool, "admin": {state,address}|None}."""
    try:
        impl = w3.eth.get_storage_at(address, EIP1967_IMPL_SLOT)
        impl_addr = Web3.to_checksum_address("0x" + bytes(impl)[-20:].hex())
    except Exception:
        return {"upgradeable": False, "admin": None}
    if impl_addr.lower() == ZERO:
        return {"upgradeable": False, "admin": None}
    admin = None
    try:
        raw = w3.eth.get_storage_at(address, EIP1967_ADMIN_SLOT)
        admin_addr = Web3.to_checksum_address("0x" + bytes(raw)[-20:].hex())
        state, a = _classify_holder(w3, admin_addr)
        admin = {"state": state if admin_addr.lower() != ZERO else "renounced", "address": a}
    except Exception:
        pass
    return {"upgradeable": True, "admin": admin}


def analyze_autonomy(w3, scope: list, pattern: str) -> dict:
    """
    scope: list of {"address": str, "role": "token"|"mechanism"|"tracker",
                    "bytecode_hex": str}   (bytecode of the LOGIC contract)
    pattern: "synthetix" | "erc4626" | "dividend" | None

    Returns {"level", "reasons": [..], "live_levers": [..], "contracts": [..],
             "distributor": {state,address}|None}
    """
    reasons, live_levers, contracts = [], [], []
    worst = "autonomous"  # ratchets toward managed

    def ratchet(level):
        nonlocal worst
        order = {"autonomous": 0, "unknown": 1, "constrained": 2, "managed": 3}
        if order[level] > order[worst]:
            worst = level

    readable_anything = False
    seen_addresses = set()

    for item in scope:
        addr = Web3.to_checksum_address(item["address"])
        if addr in seen_addresses:
            continue
        seen_addresses.add(addr)
        code = item["bytecode_hex"]
        owner = _read_owner(w3, addr, code)
        proxy = _read_proxy(w3, addr)
        present = [(sig, sev) for sig, sev in LEVERS.items() if _sel(sig) in code]
        contracts.append({
            "address": addr, "role": item["role"], "owner": owner,
            "upgradeable": proxy["upgradeable"],
            "levers": [s for s, _ in present],
        })
        if owner["state"] != "none" or present or proxy["upgradeable"]:
            readable_anything = True

        owner_state = owner["state"]
        for sig, sev in present:
            if owner_state == "renounced":
                continue  # neutralized -- nobody holds it
            if owner_state == "wallet":
                live_levers.append(f"{sig} [{item['role']}: wallet-owned]")
                ratchet("managed" if sev == "high" else "constrained")
            elif owner_state == "contract":
                live_levers.append(f"{sig} [{item['role']}: contract-owned]")
                ratchet("constrained")
            else:  # no owner() to read
                live_levers.append(f"{sig} [{item['role']}: control model unreadable]")
                ratchet("constrained")

        if proxy["upgradeable"]:
            admin = proxy["admin"] or {"state": "none"}
            if admin["state"] == "renounced" and owner_state in ("renounced", "none"):
                reasons.append(f"{item['role']} is a proxy but its admin is renounced")
            elif admin["state"] == "wallet" or (admin["state"] == "none" and owner_state == "wallet"):
                live_levers.append(f"upgradeable proxy [{item['role']}: wallet-controlled]")
                ratchet("managed")
            else:
                live_levers.append(f"upgradeable proxy [{item['role']}: controller {admin['state']}]")
                ratchet("constrained")

    # Who funds rewards in a Synthetix-style pool? notifyRewardAmount is a
    # deliberate manual act by whoever the distributor is.
    distributor = None
    if pattern == "synthetix":
        for item in scope:
            if item["role"] in ("mechanism", "token") and _sel(FUNDING_SIGNATURE) in item["bytecode_hex"]:
                dist_addr = _read_address(w3, Web3.to_checksum_address(item["address"]), "rewardsDistribution()")
                if dist_addr is None:
                    owner = _read_owner(w3, Web3.to_checksum_address(item["address"]), item["bytecode_hex"])
                    state, a = owner["state"], owner["address"]
                    reasons.append("rewards are funded via notifyRewardAmount(); distributor not readable, using owner")
                else:
                    state, a = _classify_holder(w3, dist_addr)
                distributor = {"state": state, "address": a}
                if state == "wallet":
                    live_levers.append("notifyRewardAmount() [funded by a wallet -- rewards are hand-supplied]")
                    ratchet("managed")
                elif state == "contract":
                    live_levers.append("notifyRewardAmount() [funded by a contract]")
                    ratchet("constrained")
                elif state == "renounced":
                    reasons.append("no one can fund new reward periods (distributor is zero/dead) -- rewards will run out")
                    ratchet("constrained")
                break

    if not readable_anything and not contracts:
        return {"level": "unknown", "reasons": ["nothing readable"], "live_levers": [], "contracts": [], "distributor": None}

    if worst == "autonomous" and not readable_anything:
        worst = "unknown"
    if worst == "autonomous":
        reasons.append("no live control levers found")
    return {"level": worst, "reasons": reasons, "live_levers": live_levers, "contracts": contracts, "distributor": distributor}
