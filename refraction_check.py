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

  2. Holder concentration + staking-contract discovery (redesigned --
     see refraction_holders.py for why the old "top holder is a
     contract, 30-70%" test was misfiring). Top holders are classified
     burn / pool / contract / wallet. The gate FAILS only when a
     non-burn, non-pool holder owns more than MAX_NONPOOL_HOLDER_PCT of
     supply; pools and burns are ignored here (whether pool concentration
     is good or bad depends on the LP lock, checked separately). There
     is no minimum -- a brand-new token with nothing staked yet is fine.
     Every holder that is a plain "contract" is ALSO scanned as a
     candidate staking/vault contract (_find_staking_holder). This is
     where real staking contracts get found: they are usually SEPARATE
     contracts from the token, so scanning only the token's own bytecode
     (all this check used to do) could never find one.

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
from refraction_autonomy import analyze_autonomy
from refraction_payouts import verify_payouts, verify_vault_yield

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

REWARD_TOKEN_ACCESSORS = [
    "rewardsToken()", "rewardToken()",
    # dividend-tracker / fork variants (names seen in published templates)
    "dividendToken()", "rewardTokenAddress()", "getRewardToken()", "payoutToken()", "getPayoutToken()",
]

# Classic "reflection" pattern (RFI, then SafeMoon and hundreds of direct
# forks) -- architecturally nothing like Synthetix/ERC-4626. No separate
# staking contract at all: every transfer silently redistributes a cut to
# all holders via a rebasing-balance trick baked directly into the
# token's own _transfer(). This is the ORIGINAL sense of "reflection
# token" as a term, distinct from the staking/vault patterns this file
# already detects.
#
# The core state (_rOwned/_tOwned/_rTotal/_tTotal) is almost always
# declared private in the standard implementation, so it has no ABI
# selector to scan for -- these are the PUBLIC/EXTERNAL function names
# from that same standard codebase instead, which is heavily and
# consistently forked, giving real confidence in this signature set.
# Purely diagnostic, never gates a buy: pays in the SAME token (self-
# referential), not a genuine external asset, so it can't satisfy
# reward_token_mainstream even when detected -- see summarize_reflection().
CLASSIC_REFLECTION_SIGNATURES = [
    "deliver(uint256)",
    "reflectionFromToken(uint256,bool)",
    "tokenFromReflection(uint256)",
    "excludeFromReward(address)",
    "includeInReward(address)",
    "isExcludedFromReward(address)",
    # Original Reflect.Finance naming (checked against its published
    # source) -- forks are inconsistent; some keep this pair, some use
    # the ...Reward pair above, so both are scanned.
    "excludeAccount(address)",
    "includeAccount(address)",
    "isExcluded(address)",
    "totalFees()",
]
# The two conversion functions are the distinctive part of the pattern
# (they exist because balances are stored as "reflections" and converted
# on read). Requiring at least one of them, on top of 2+ total matches,
# keeps generic tax tokens that merely share names like totalFees() or
# isExcluded() from being mislabeled as reflection tokens.
CLASSIC_REFLECTION_CORE = ("reflectionFromToken(uint256,bool)", "tokenFromReflection(uint256)")
CLASSIC_REFLECTION_MIN_MATCHES = 2

# Dividend-paying tokens -- the pattern behind "hold this token, earn BTC /
# ETH / USDC / BUSD" contracts. Unlike classic reflection (which pays you
# more of the SAME token by inflating your balance), these pay a SEPARATE
# asset that the holder withdraws. Based on Roger Wu's ERC-1726 draft
# ("Dividend-Paying Token Standard": dividendOf, distributeDividends,
# withdrawDividend) plus its widely copied optional interface
# (withdrawableDividendOf, withdrawnDividendOf, accumulativeDividendOf).
# ERC-1726 was never finalized -- it stayed a Draft -- but the reference
# implementation is copied into a huge number of reward tokens. Some forks
# add a reward-token argument to support several payout assets, so those
# signatures are scanned too. Signatures checked against published source.
DIVIDEND_SIGNATURES = [
    "withdrawDividend()",
    "withdrawDividend(address)",
    "dividendOf(address)",
    "dividendOf(address,address)",
    "distributeDividends()",
    "withdrawableDividendOf(address)",
    "withdrawnDividendOf(address)",
    "accumulativeDividendOf(address)",
]
DIVIDEND_CORE = ("withdrawDividend()", "withdrawDividend(address)")  # the "pull your payout" call
DIVIDEND_MIN_MATCHES = 2
# Tracker-style tokens (BABYDOGE-lineage forks: DeFi-IRA, BasePrinter, ...)
# keep the pay-out machinery in a SEPARATE tracker contract and only expose
# forwarders on the token, so the ERC-1726 core above may not be in the
# token's own code. These selectors identify a tracker.
TRACKER_SIGNATURES = [
    "process(uint256)",
    "getNumberOfTokenHolders()",
    "getAccountAtIndex(uint256)",
    "setBalance(address,uint256)",
    "claimWait()",
    "withdrawableDividendOf(address)",
    "minimumTokenBalanceForDividends()",
]

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
# no_admin_keys is now an informational/bonus signal by default. As a hard gate
# it could only ever pass contracts that never had an owner (renounceOwnership()
# is in the bytecode of every OpenZeppelin Ownable token even AFTER the owner
# renounced). The real question -- does anyone still hold the levers -- is the
# autonomy_ok gate below, which reads live owner state.
REQUIRE_NO_ADMIN_KEYS = _env_flag("REFRACTION_REQUIRE_NO_ADMIN_KEYS", "0")
REQUIRE_AUTONOMY = _env_flag("REFRACTION_REQUIRE_AUTONOMY", "1")
REQUIRE_PAYOUT_PROOF = _env_flag("REFRACTION_REQUIRE_PAYOUT_PROOF", "1")
ALLOW_CONSTRAINED = _env_flag("REFRACTION_ALLOW_CONSTRAINED", "0")
ALLOW_EVENT_ONLY = _env_flag("REFRACTION_ALLOW_EVENT_ONLY_PROOF", "0")
REQUIRE_NO_INFLATION_RISK = _env_flag("REFRACTION_REQUIRE_NO_INFLATION_RISK", "1")
# Largest share any single holder may own UNLESS it has a legitimate
# reason to (burn address, liquidity pool, or a discovered staking/vault
# contract). Default 5%. No minimum: a fresh token with nothing staked
# yet must not fail for that. Loosen with REFRACTION_MAX_NONPOOL_HOLDER_PCT.
MAX_NONPOOL_HOLDER_PCT = float(os.environ.get("REFRACTION_MAX_NONPOOL_HOLDER_PCT", "5"))
# Also scan top-holder contracts for a Synthetix/ERC-4626 mechanism.
SCAN_HOLDER_CONTRACTS = _env_flag("REFRACTION_SCAN_HOLDER_CONTRACTS", "1")


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


def _check_classic_reflection(bytecode_hex: str) -> dict:
    matches = _match_function_set(bytecode_hex, CLASSIC_REFLECTION_SIGNATURES)
    found = [sig for sig, present in matches.items() if present]
    has_core = any(sig in found for sig in CLASSIC_REFLECTION_CORE)
    return {
        "detected": len(found) >= CLASSIC_REFLECTION_MIN_MATCHES and has_core,
        "matched_selectors": found,
    }


def _find_embedded_reward_assets(bytecode_hex: str) -> list:
    """Compiled code never contains the word "WBTC" -- but a hardcoded /
    immutable / constant reward asset is baked into the bytecode as its
    20-byte ADDRESS, so scan for the known payout assets' addresses. Misses
    reward tokens that are set at deploy time and kept in storage; and an
    address in the code proves the contract REFERENCES that asset (e.g. WETH
    shows up in any swap logic), not that it pays it -- so this is only
    reported alongside a detected dividend pattern."""
    haystack = bytecode_hex.lower()
    return [label for addr, label in MAINSTREAM_REWARD_TOKENS.items() if addr[2:].lower() in haystack]


def _check_dividend_pattern(bytecode_hex: str) -> dict:
    matches = _match_function_set(bytecode_hex, DIVIDEND_SIGNATURES)
    found = [sig for sig, present in matches.items() if present]
    has_core = any(sig in found for sig in DIVIDEND_CORE)
    t_matches = _match_function_set(bytecode_hex, TRACKER_SIGNATURES)
    t_found = [sig for sig, present in t_matches.items() if present]
    erc1726_style = len(found) >= DIVIDEND_MIN_MATCHES and has_core
    tracker_style = len(t_found) >= 3 and "withdrawableDividendOf(address)" in t_found
    detected = erc1726_style or tracker_style
    found = found + [sig for sig in t_found if sig not in found]
    return {
        "detected": detected,
        "matched_selectors": found,
        "embedded_reward_assets": _find_embedded_reward_assets(bytecode_hex) if detected else [],
    }


def _read_address_accessor(address: str, signature: str):
    """Call a no-argument view that returns an address (stakingToken(),
    asset(), ...). Returns a checksummed address, or None if the function
    is missing, the call failed, or it returned the zero address."""
    try:
        data = bytes(Web3.keccak(text=signature))[:4]
        result = w3.eth.call({"to": address, "data": data})
    except Exception:
        return None
    if len(result) < 32:
        return None
    candidate = Web3.to_checksum_address("0x" + bytes(result)[-20:].hex())
    return None if candidate == Web3.to_checksum_address(ZERO_ADDRESS) else candidate


def _staking_link(address: str, pattern: str, target: str):
    """Does this candidate staking/vault contract actually work with OUR
    token? True (its stakingToken()/asset() is our token), False (it's
    for a different token), or None (accessor missing -- can't tell)."""
    signature = "asset()" if pattern == "erc4626" else "stakingToken()"
    linked_to = _read_address_accessor(address, signature)
    if linked_to is None:
        return None
    return linked_to == target


def _find_staking_holder(holders: dict, target: str):
    """
    Scan each top holder classified as a plain 'contract' for a Synthetix
    or ERC-4626 reward mechanism. A real staking contract is usually a
    SEPARATE contract from the token and holds the staked tokens, so it
    shows up in the holder list -- scanning only the token's own bytecode
    can never find it. Candidates that positively link to a DIFFERENT
    token are skipped. Returns the best candidate dict, or None.
    """
    best = None
    for h in holders.get("holders", []):
        if h.get("kind") != "contract":
            continue
        addr = Web3.to_checksum_address(h["address"])
        try:
            logic = _resolve_logic_address(addr)
            iface = _interface_match(_get_bytecode_hex(logic))
        except Exception:
            continue
        if not iface["is_match"]:
            continue
        linked = _staking_link(addr, iface["pattern"], target)
        if linked is False:
            continue
        candidate = {
            "address": addr,
            "pattern": iface["pattern"],
            "iface": iface,
            "linked": linked,
            "holder_pct": h["pct"],
        }
        # Prefer a verified link to our token, then the larger stake.
        if best is None or (linked is True, h["pct"]) > (best["linked"] is True, best["holder_pct"]):
            best = candidate
    return best


def _evaluate_holder_gate(holders: dict, exempt_address=None) -> bool:
    """
    Passes unless a non-burn, non-pool holder owns more than
    MAX_NONPOOL_HOLDER_PCT. Burns and pools are ignored (pool
    concentration is judged by the LP-lock check, not here). There is
    deliberately NO minimum. A discovered staking contract is exempt --
    lots of supply sitting in the reward contract is the point, not a
    risk.
    """
    if not holders.get("ok"):
        return False
    exempt = exempt_address.lower() if exempt_address else None
    for h in holders.get("holders", []):
        if h["kind"] in ("burn", "pool"):
            continue
        if exempt and h["address"].lower() == exempt:
            continue
        if h["pct"] > MAX_NONPOOL_HOLDER_PCT:
            return False
    return True


def summarize_reflection(result: dict) -> str:
    """
    One-line, human-readable answer to "does this pay reflections, and in
    what" -- built from a full check_refraction() result. Used everywhere
    this needs to be shown (!check, !rlog, digest, alerts) so the wording
    only lives in one place. Reports on EVERY candidate regardless of
    passes_all, since this is diagnostic, not gating.
    """
    d = result["detail"]
    interface, reward = d["interface"], d["reward"]
    classic = d.get("classic_reflection", {})
    mechanism = d.get("mechanism") or {}
    dividend = d.get("dividend", {})
    payouts = d.get("payouts") or {}
    autonomy = d.get("autonomy") or {}

    tail = ""
    if payouts.get("ran"):
        tail += f" · payouts {payouts['proof']}"
    if autonomy.get("level"):
        tail += f" · {autonomy['level']}"

    if interface.get("is_match"):
        label = {"erc4626": "ERC-4626 vault", "synthetix": "Synthetix staking",
                 "dividend": "dividend-paying token"}.get(interface["pattern"], interface["pattern"])
        if mechanism.get("where") == "holder_contract":
            addr = mechanism["address"]
            link = {True: "confirmed for this token", False: "", None: "link to this token unverified"}[mechanism.get("linked")]
            label += f" via separate contract {addr[:8]}…{addr[-4:]}" + (f" ({link})" if link else "")
        elif mechanism.get("where") == "tracker":
            addr = mechanism["address"]
            label += f" via tracker {addr[:8]}…{addr[-4:]}"
        if reward.get("ok") and reward.get("reward_token"):
            payout = reward["label"] if reward.get("label") else (
                f"unlabeled asset ({reward['reward_token']})" if not reward.get("is_mainstream") else reward["reward_token"])
            if reward.get("observed"):
                payout += " (observed in payouts)"
            return f"reflection: {label} — pays {payout}{tail}"
        assets = dividend.get("embedded_reward_assets") or []
        hint = f"; code references {', '.join(assets)}" if assets else ""
        return f"reflection: {label} — reward asset undetermined{hint}{tail}"

    if dividend.get("detected"):
        assets = dividend.get("embedded_reward_assets") or []
        paid = (f"address found in code: {', '.join(assets)}" if assets
                else "payout asset not visible in code -- likely set at deploy time, read the contract")
        return (f"reflection: dividend-paying pattern ({', '.join(dividend['matched_selectors'])}) "
                f"— pays a separate asset; {paid}{tail}")

    if classic.get("detected"):
        return f"reflection: classic pattern ({', '.join(classic['matched_selectors'])}) — pays in itself, not a genuine external asset"

    return "reflection: none detected"


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


def _find_dividend_tracker(token_address: str, bytecode_hex: str):
    """Tracker-style dividend tokens expose dividendTracker() on the token.
    Returns (tracker_address | None, tracker_logic_bytecode_hex)."""
    if _selector("dividendTracker()") not in bytecode_hex:
        return None, ""
    tracker = _read_address_accessor(token_address, "dividendTracker()")
    if not tracker:
        return None, ""
    try:
        return tracker, _get_bytecode_hex(_resolve_logic_address(tracker))
    except Exception:
        return tracker, ""


def _resolve_reward(addresses: list, target: str, pattern):
    """Read the reward asset from the first contract that names one.
    ERC-4626 vaults have no 'reward token' -- yield accrues in asset()."""
    for a in addresses:
        r = _get_reward_token(a, target)
        if r["ok"]:
            return r
    if pattern == "erc4626":
        for a in addresses:
            asset = _read_address_accessor(a, "asset()")
            if asset:
                if asset == target:
                    return {"ok": True, "reward_token": asset, "is_mainstream": False,
                            "label": "pays in itself -- not an external asset", "via": "asset()"}
                label = MAINSTREAM_REWARD_TOKENS.get(asset)
                return {"ok": True, "reward_token": asset, "is_mainstream": label is not None, "label": label, "via": "asset()"}
    return {"ok": False, "reward_token": None, "is_mainstream": False, "label": None}


def check_refraction(address: str) -> dict:
    """
    Runs every step regardless of which are required, so you always get
    full diagnostic info back -- then applies the configured hard gates
    (REFRACTION_REQUIRE_* env vars) to decide passes_all.

    Expensive work (autonomy reads, payout-log scans) runs ONLY when a
    qualifying pattern was found, so the vast majority of scanned tokens
    never pay for it.
    """
    target = Web3.to_checksum_address(address)
    logic_address = _resolve_logic_address(target)
    bytecode_hex = _get_bytecode_hex(logic_address)

    own_interface = _interface_match(bytecode_hex)
    holders = get_holder_concentration(w3, target)

    tracker_addr, tracker_code = _find_dividend_tracker(target, bytecode_hex)
    dividend = _check_dividend_pattern(bytecode_hex + tracker_code)

    # Where does the reward mechanism live? Often in a SEPARATE contract
    # from the token, so if the token itself doesn't match, look at the
    # top holders too (see _find_staking_holder).
    mechanism = {"where": "token", "address": target, "linked": None, "tracker": tracker_addr}
    interface = own_interface
    staking = None
    if not own_interface["is_match"] and SCAN_HOLDER_CONTRACTS and holders.get("ok"):
        staking = _find_staking_holder(holders, target)
        if staking:
            interface = staking["iface"]
            mechanism = {"where": "holder_contract", "address": staking["address"],
                         "linked": staking["linked"], "tracker": tracker_addr}

    # Dividend-paying tokens are a third qualifying pattern.
    if not interface["is_match"] and dividend["detected"]:
        interface = {"is_match": True, "pattern": "dividend",
                     "synthetix": own_interface["synthetix"], "erc4626": own_interface["erc4626"]}
        mechanism = {"where": "tracker" if tracker_addr else "token", "address": tracker_addr or target,
                     "linked": None, "tracker": tracker_addr}

    pattern = interface["pattern"] if interface["is_match"] else None

    # Accessor calls must go to the address that holds the STORAGE (the
    # proxy / original address), not the implementation behind it --
    # calling an implementation directly reads its empty storage.
    reward_sources = [mechanism["address"]] + ([target] if mechanism["address"] != target else [])
    reward = _resolve_reward(reward_sources, target, pattern)
    is_gauge = _is_aerodrome_gauge(target)
    admin_risk = _check_admin_risk(bytecode_hex)
    vault_risk = _check_vault_liquidity_risk(mechanism["address"], interface["pattern"])
    classic_reflection = _check_classic_reflection(bytecode_hex)

    autonomy = payouts = None
    if pattern:
        scope = [{"address": target, "role": "token", "bytecode_hex": bytecode_hex}]
        if mechanism["address"] != target:
            try:
                scope.append({
                    "address": mechanism["address"],
                    "role": "tracker" if mechanism["where"] == "tracker" else "mechanism",
                    "bytecode_hex": _get_bytecode_hex(_resolve_logic_address(mechanism["address"])),
                })
            except Exception:
                pass
        if tracker_addr and tracker_addr != mechanism["address"] and tracker_code:
            scope.append({"address": tracker_addr, "role": "tracker", "bytecode_hex": tracker_code})
        autonomy = analyze_autonomy(w3, scope, pattern)

        if pattern == "erc4626":
            payouts = verify_vault_yield(w3, mechanism["address"])
        else:
            payers = [mechanism["address"]]
            if pattern == "dividend":
                payers.append(target)
                if tracker_addr:
                    payers.append(tracker_addr)
            if reward.get("ok") and reward.get("reward_token") and reward["reward_token"] != target:
                assets = {reward["reward_token"]: reward.get("label") or reward["reward_token"]}
            else:
                assets = dict(MAINSTREAM_REWARD_TOKENS)
            payouts = verify_payouts(w3, target, payers, assets)

            # If the contract never named its reward asset, the payouts
            # themselves can: whichever asset actually went out to holders.
            observed = payouts.get("reward_asset_observed")
            if not reward.get("ok") and observed:
                lab = MAINSTREAM_REWARD_TOKENS.get(Web3.to_checksum_address(observed["address"]))
                reward = {"ok": True, "reward_token": observed["address"], "is_mainstream": lab is not None,
                          "label": lab, "observed": True}

            # One or two senders pushing payouts = a person is distributing.
            if payouts["trigger"]["verdict"] == "manual_push" and autonomy["level"] != "managed":
                autonomy["live_levers"].append("payouts are pushed by one or two senders -- a person is distributing them")
                autonomy["level"] = "managed"

    holder_pass = _evaluate_holder_gate(holders, exempt_address=staking["address"] if staking else None)

    # Not applicable (Synthetix-pattern) or the read failed -> don't penalize;
    # only fail this step when we positively confirmed low supply.
    vault_supply_safe = not (vault_risk.get("applicable") and vault_risk.get("ok") and vault_risk.get("inflation_risk"))

    autonomy_ok = bool(autonomy and (autonomy["level"] == "autonomous"
                                     or (autonomy["level"] == "constrained" and ALLOW_CONSTRAINED)))
    proof = payouts["proof"] if payouts else None
    payout_proven = bool(proof == "strong" or (proof in ("events_only", "drift_only") and ALLOW_EVENT_ONLY))

    steps = {
        "interface_match": interface["is_match"],
        "holder_concentration_pass": holder_pass,
        "reward_token_mainstream": reward["is_mainstream"],
        "aerodrome_gauge": is_gauge,
        "no_admin_keys": admin_risk["no_admin_keys"],
        "vault_supply_safe": vault_supply_safe,
        "autonomy_ok": autonomy_ok,
        "payout_proven": payout_proven,
    }
    gates = {
        "interface_match": REQUIRE_INTERFACE,
        "holder_concentration_pass": REQUIRE_HOLDER_CONCENTRATION,
        "reward_token_mainstream": REQUIRE_REWARD_TOKEN,
        "aerodrome_gauge": REQUIRE_AERODROME_GAUGE,
        "no_admin_keys": REQUIRE_NO_ADMIN_KEYS,
        "vault_supply_safe": REQUIRE_NO_INFLATION_RISK,
        "autonomy_ok": REQUIRE_AUTONOMY,
        "payout_proven": REQUIRE_PAYOUT_PROOF,
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
            "classic_reflection": classic_reflection,
            "mechanism": mechanism,
            "dividend": dividend,
            "autonomy": autonomy,
            "payouts": payouts,
        },
    }
