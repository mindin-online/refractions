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
     Also distinguishes the common "pays in itself" pattern (stake TOKEN,
     earn more TOKEN) from a genuine external-asset payout -- the former
     is flagged with an explicit label, not just an unmatched address,
     since it's a materially different (weaker) structure than paying
     out in an already-established asset.

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

ERC4626_ACCOUNTING_ABI = [
    {"inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "totalAssets", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "asset", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
]
ERC20_BALANCE_ABI = [
    {"inputs": [{"type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]
# Below this many raw shares outstanding, a vault is in the highest-risk
# window for the classic ERC-4626 inflation attack (first depositor gets
# 1 wei, donates a huge amount directly, inflates share price, later
# depositors lose funds to rounding). This is a coarse proxy, not proof
# the contract mints dead shares or uses virtual offsets -- it just means
# the most dangerous window has likely passed once supply is meaningful.
MIN_VAULT_SUPPLY_RAW = int(os.environ.get("REFRACTION_MIN_VAULT_SUPPLY_RAW", "100000"))


def _env_flag(name: str, default: str) -> bool:
    return os.environ.get(name, default) not in ("0", "false", "False", "")


REQUIRE_INTERFACE = _env_flag("REFRACTION_REQUIRE_INTERFACE", "1")
REQUIRE_HOLDER_CONCENTRATION = _env_flag("REFRACTION_REQUIRE_HOLDER_CONCENTRATION", "1")
REQUIRE_REWARD_TOKEN = _env_flag("REFRACTION_REQUIRE_REWARD_TOKEN", "1")
REQUIRE_AERODROME_GAUGE = _env_flag("REFRACTION_REQUIRE_AERODROME_GAUGE", "0")
REQUIRE_NO_ADMIN_KEYS = _env_flag("REFRACTION_REQUIRE_NO_ADMIN_KEYS", "1")
REQUIRE_NO_INFLATION_RISK = _env_flag("REFRACTION_REQUIRE_NO_INFLATION_RISK", "1")
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


def _get_reward_token(address: str, target: str) -> dict:
    for sig in REWARD_TOKEN_ACCESSORS:
        try:
            data = bytes(Web3.keccak(text=sig))[:4]
            result = w3.eth.call({"to": address, "data": data})
            if len(result) >= 32:
                candidate = Web3.to_checksum_address("0x" + result[-20:].hex())
                if candidate == target:
                    return {"ok": True, "reward_token": candidate, "is_mainstream": False, "label": "pays in itself -- not an external asset"}
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


def _check_vault_liquidity_risk(address: str, pattern: str) -> dict:
    """
    Only meaningful for ERC-4626 vaults -- Synthetix-pattern contracts
    don't expose totalAssets()/asset(), so this is a pass-through (not
    applicable, not penalized) for those.

    Checks two of the four risks from the standard ERC-4626 liquidity
    writeup -- specifically the two that are actually checkable from
    outside a contract before buying in, as opposed to things a vault's
    own developer would need to fix:

    1. Inflation-attack exposure (see MIN_VAULT_SUPPLY_RAW above).
    2. Liquidity buffer: the vault's own direct balance of its underlying
       asset vs totalAssets(). A vault holding little to none of its own
       asset directly has deployed essentially everything elsewhere
       (lending, other pools) -- a bank-run/insolvency risk if a large
       withdrawal arrives and unwinding that external position isn't
       instant. This is informational only (not gated), since many
       legitimate vaults intentionally deploy near 100% and are still
       fine depending on their yield source -- there's no clean universal
       "safe" threshold to hard-gate on.

    NOT checked, deliberately, rather than faked:
    - MEV/sandwich risk on deposit/withdraw is about how a caller
      interacts with the vault, not a property of the vault contract
      itself -- already mitigated on our end via slippage_bps in the
      swap quote (see wallet_funding.py / base_buy.py), not something
      to detect about the target.
    - Oracle manipulation requires knowing which specific price source a
      given vault uses internally, which varies per-vault and isn't
      generically introspectable from outside. This is a real gap, not
      something worth faking a check for.
    """
    if pattern != "erc4626":
        return {"applicable": False}

    try:
        contract = w3.eth.contract(address=address, abi=ERC4626_ACCOUNTING_ABI)
        total_supply = contract.functions.totalSupply().call()
        total_assets = contract.functions.totalAssets().call()
        asset_address = contract.functions.asset().call()
    except Exception as e:
        return {"applicable": True, "ok": False, "reason": f"could not read vault accounting: {e}"}

    inflation_risk = total_supply < MIN_VAULT_SUPPLY_RAW

    liquidity_buffer_pct = None
    try:
        asset_contract = w3.eth.contract(address=Web3.to_checksum_address(asset_address), abi=ERC20_BALANCE_ABI)
        vault_own_balance = asset_contract.functions.balanceOf(address).call()
        if total_assets > 0:
            liquidity_buffer_pct = (vault_own_balance / total_assets) * 100
    except Exception:
        pass

    return {
        "applicable": True,
        "ok": True,
        "total_supply": total_supply,
        "total_assets": total_assets,
        "inflation_risk": inflation_risk,
        "liquidity_buffer_pct": liquidity_buffer_pct,
    }


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
    reward = _get_reward_token(logic_address, target)
    is_gauge = _is_aerodrome_gauge(target)
    admin_risk = _check_admin_risk(bytecode_hex)
    vault_risk = _check_vault_liquidity_risk(logic_address, interface["pattern"])

    holder_pass = (
        holders["ok"]
        and holders["top_holder_is_contract"]
        and MIN_HOLDER_PCT <= holders["top_holder_pct"] <= MAX_HOLDER_PCT
    )

    # Not applicable (Synthetix-pattern) or the read failed -> don't penalize;
    # only fail this step when we positively confirmed low supply.
    vault_supply_safe = not (vault_risk.get("applicable") and vault_risk.get("ok") and vault_risk.get("inflation_risk"))

    steps = {
        "interface_match": interface["is_match"],
        "holder_concentration_pass": holder_pass,
        "reward_token_mainstream": reward["is_mainstream"],
        "aerodrome_gauge": is_gauge,
        "no_admin_keys": admin_risk["no_admin_keys"],
        "vault_supply_safe": vault_supply_safe,
    }
    gates = {
        "interface_match": REQUIRE_INTERFACE,
        "holder_concentration_pass": REQUIRE_HOLDER_CONCENTRATION,
        "reward_token_mainstream": REQUIRE_REWARD_TOKEN,
        "aerodrome_gauge": REQUIRE_AERODROME_GAUGE,
        "no_admin_keys": REQUIRE_NO_ADMIN_KEYS,
        "vault_supply_safe": REQUIRE_NO_INFLATION_RISK,
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
            "vault_risk": vault_risk,
        },
    }
