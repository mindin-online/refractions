"""
refraction_check.py

Multi-step "refraction token" fingerprint for Base contracts. Each step
is independently toggleable via env vars (default: interface + holder
concentration + reward token are ON, Aerodrome gauge is OFF by default --
see note below), so the pipeline is a hard AND-gate by default without
needing a code change to loosen any one step.

Steps:
  1. Interface match: Synthetix StakingRewards pattern OR ERC-4626 vault
     pattern. Detected by scanning contract BYTECODE for each function's
     4-byte selector, not by trial-calling the functions.

     Why bytecode scanning instead of calling, like the original version
     of this check did: view functions (rewardPerToken, earned, etc.) are
     safe to trial-call, but the state-mutating ones (stake, deposit,
     withdraw) almost always revert in a simulated call regardless of
     whether the function exists, because they try to move tokens from an
     account with no real balance/approval. That made "does stake()
     exist" untestable by calling it. Checking whether the function's
     selector appears in the deployed bytecode answers the same question
     without that false-negative problem, and it's how most bytecode
     fingerprinting tools (Slither, etc.) do this. If the contract is an
     EIP-1967 proxy, this follows it to the implementation address first
     and scans that -- otherwise you'd just be scanning a thin proxy
     stub that never shows the real function set.

  2. Top holder concentration: top holder is a contract (not an EOA) and
     holds between MIN_HOLDER_PCT and MAX_HOLDER_PCT of supply. Needs
     ETHERSCAN_API_KEY (Pro plan) -- see refraction_holders.py.

  3. Reward token is a mainstream asset (USDC / WETH / cbBTC on Base),
     read from the contract's rewardsToken()/rewardToken() accessor.

  4. Registered as an Aerodrome gauge, checked against Aerodrome's own
     Voter contract via isGauge() -- a real on-chain registry lookup, not
     a guess. Voter address sourced from Aerodrome's docs; worth
     re-confirming against aerodrome.finance if it ever stops matching,
     in case of a redeploy. OFF by default: this is one specific
     sub-pattern (LP fee-sharing via Aerodrome specifically), not
     something every refraction token will be, so it's a bonus signal
     rather than a hard gate unless you flip it on.

  5. No admin-key / mutability red flags: same bytecode-selector scan as
     step 1, but inverted -- instead of confirming good selectors exist,
     this checks whether common OpenZeppelin-style admin selectors exist
     at all (owner(), renounceOwnership(), transferOwnership(address),
     pause()/unpause(), an arbitrary mint(address,uint256), blacklist(),
     excludeFromFee()). Presence of any of these is a red flag -- it
     means someone can still change behavior after launch.

     Real limitation, not just theoretical: this only catches the
     standard/naive versions of these patterns. A determined rug can
     rename the function or gate the same capability behind an
     unrecognizable selector, and this check would show clean. Treat a
     pass here as "no obvious admin backdoor," not "provably immutable."
     mint(address,uint256) is deliberately distinct from ERC-4626's own
     mint(uint256,address) in step 1 -- different argument order means a
     different selector, so a legitimate vault's mint doesn't trip this.

IMPORTANT CAVEAT (unchanged from the original version of this check):
none of this is a securities-law determination. It confirms code shape
and on-chain facts (interface, holder concentration, reward asset, gauge
registration, admin-selector presence) -- not distribution history,
marketing, or who actually controls reward funding, which is what
Howey-style analysis turns on.
"""
import os
from web3 import Web3

from refraction_holders import get_holder_concentration

RPC_URL = os.environ.get("RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# --- known Base addresses ---
MAINSTREAM_REWARD_TOKENS = {
    Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): "USDC",
    Web3.to_checksum_address("0x4200000000000000000000000000000000000006"): "WETH",
    Web3.to_checksum_address("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"): "cbBTC",
}
AERODROME_VOTER = Web3.to_checksum_address("0xF5601f95708256a118Ef5971820327F362442d2D")
EIP1967_IMPL_SLOT = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bb", 16)
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

AERODROME_VOTER_ABI = [
    {"inputs": [{"type": "address"}], "name": "isGauge", "outputs": [{"type": "bool"}], "stateMutability": "view", "type": "function"},
]

# --- function sets, as solidity signatures ---
SYNTHETIX_SIGNATURES = [
    "rewardPerTokenStored()",
    "userRewardPerTokenPaid(address)",
    "rewardPerToken()",
    "earned(address)",
    "stake(uint256)",
    "withdraw(uint256)",
    "getReward()",
]

ERC4626_SIGNATURES = [
    "asset()",
    "totalAssets()",
    "convertToShares(uint256)",
    "convertToAssets(uint256)",
    "deposit(uint256,address)",
    "mint(uint256,address)",
    "withdraw(uint256,address,address)",
    "redeem(uint256,address,address)",
]

REWARD_TOKEN_ACCESSORS = ["rewardsToken()", "rewardToken()"]

ADMIN_RISK_SIGNATURES = [
    "owner()",
    "renounceOwnership()",
    "transferOwnership(address)",
    "pause()",
    "unpause()",
    "mint(address,uint256)",   # deliberately NOT the same selector as ERC-4626's mint(uint256,address)
    "blacklist(address)",
    "excludeFromFee(address)",
]


def _env_flag(name: str, default: str) -> bool:
    return os.environ.get(name, default) not in ("0", "false", "False", "")


REQUIRE_INTERFACE = _env_flag("REFRACTION_REQUIRE_INTERFACE", "1")
REQUIRE_HOLDER_CONCENTRATION = _env_flag("REFRACTION_REQUIRE_HOLDER_CONCENTRATION", "1")
REQUIRE_REWARD_TOKEN = _env_flag("REFRACTION_REQUIRE_REWARD_TOKEN", "1")
REQUIRE_AERODROME_GAUGE = _env_flag("REFRACTION_REQUIRE_AERODROME_GAUGE", "0")
REQUIRE_NO_ADMIN_KEYS = _env_flag("REFRACTION_REQUIRE_NO_ADMIN_KEYS", "1")
MIN_HOLDER_PCT = float(os.environ.get("REFRACTION_MIN_HOLDER_PCT", "30"))
MAX_HOLDER_PCT = float(os.environ.get("REFRACTION_MAX_HOLDER_PCT", "70"))


def _selector(signature: str) -> str:
    return bytes(Web3.keccak(text=signature))[:4].hex()


def _resolve_logic_address(address: str) -> str:
    """Follow an EIP-1967 proxy to its implementation, if this is one."""
    try:
        raw = w3.eth.get_storage_at(address, EIP1967_IMPL_SLOT)
        impl = Web3.to_checksum_address("0x" + raw[-20:].hex())
        if impl != Web3.to_checksum_address(ZERO_ADDRESS) and w3.eth.get_code(impl):
            return impl
    except Exception:
        pass
    return address


def _get_bytecode_hex(address: str) -> str:
    return w3.eth.get_code(address).hex().lower()


def _match_function_set(bytecode_hex: str, signatures: list) -> dict:
    return {sig: (_selector(sig) in bytecode_hex) for sig in signatures}


def _interface_match(bytecode_hex: str) -> dict:
    synthetix = _match_function_set(bytecode_hex, SYNTHETIX_SIGNATURES)
    erc4626 = _match_function_set(bytecode_hex, ERC4626_SIGNATURES)
    synthetix_match = all(synthetix.values())
    erc4626_match = all(erc4626.values())
    return {
        "is_match": synthetix_match or erc4626_match,
        "pattern": "synthetix" if synthetix_match else ("erc4626" if erc4626_match else None),
        "synthetix": synthetix,
        "erc4626": erc4626,
    }


def _get_reward_token(address: str) -> dict:
    for sig in REWARD_TOKEN_ACCESSORS:
        try:
            data = bytes(Web3.keccak(text=sig))[:4]
            result = w3.eth.call({"to": address, "data": data})
            if len(result) >= 32:
                candidate = Web3.to_checksum_address("0x" + result[-20:].hex())
                label = MAINSTREAM_REWARD_TOKENS.get(candidate)
                return {"ok": True, "reward_token": candidate, "is_mainstream": label is not None, "label": label}
        except Exception:
            continue
    return {"ok": False, "reward_token": None, "is_mainstream": False, "label": None}


def _is_aerodrome_gauge(address: str) -> bool:
    try:
        voter = w3.eth.contract(address=AERODROME_VOTER, abi=AERODROME_VOTER_ABI)
        return bool(voter.functions.isGauge(address).call())
    except Exception:
        return False


def _check_admin_risk(bytecode_hex: str) -> dict:
    matches = _match_function_set(bytecode_hex, ADMIN_RISK_SIGNATURES)
    found = [sig for sig, present in matches.items() if present]
    return {"no_admin_keys": len(found) == 0, "flagged_selectors": found}


def check_refraction(address: str) -> dict:
    """
    Runs every step regardless of which are required, so you always get
    full diagnostic info back -- then applies the configured hard gates
    (REFRACTION_REQUIRE_* env vars) to decide passes_all.
    """
    target = Web3.to_checksum_address(address)
    logic_address = _resolve_logic_address(target)
    bytecode_hex = _get_bytecode_hex(logic_address)

    interface = _interface_match(bytecode_hex)
    holders = get_holder_concentration(w3, target)
    reward = _get_reward_token(logic_address)
    is_gauge = _is_aerodrome_gauge(target)
    admin_risk = _check_admin_risk(bytecode_hex)

    holder_pass = (
        holders["ok"]
        and holders["top_holder_is_contract"]
        and MIN_HOLDER_PCT <= holders["top_holder_pct"] <= MAX_HOLDER_PCT
    )

    steps = {
        "interface_match": interface["is_match"],
        "holder_concentration_pass": holder_pass,
        "reward_token_mainstream": reward["is_mainstream"],
        "aerodrome_gauge": is_gauge,
        "no_admin_keys": admin_risk["no_admin_keys"],
    }
    gates = {
        "interface_match": REQUIRE_INTERFACE,
        "holder_concentration_pass": REQUIRE_HOLDER_CONCENTRATION,
        "reward_token_mainstream": REQUIRE_REWARD_TOKEN,
        "aerodrome_gauge": REQUIRE_AERODROME_GAUGE,
        "no_admin_keys": REQUIRE_NO_ADMIN_KEYS,
    }
    passes_all = all(steps[k] for k, required in gates.items() if required)

    return {
        "address": target,
        "logic_address": logic_address if logic_address != target else None,
        "passes_all": passes_all,
        "steps": steps,
        "gates_active": [k for k, v in gates.items() if v],
        "detail": {
            "interface": interface,
            "holders": holders,
            "reward": reward,
            "admin_risk": admin_risk,
        },
    }
