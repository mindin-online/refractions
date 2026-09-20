"""
wallet_funding.py

Shared, top-level funding check meant to sit in front of every Base buy
path -- base_buy.py's execute_buy(), and eventually mojo_hawk.py's own
buy execution once wired in there too. The idea: a buy shouldn't care
whether the wallet's currently holding ETH or USDC -- it just needs
enough of whatever the target pair is quoted in. This checks both
balances and, if the needed currency is short, converts enough of the
other one to cover it.

Gas on Base is always paid in ETH, so MIN_ETH_RESERVE_ETH is a hard
floor that's never swapped away, even when a buy needs USDC and there's
technically "enough" ETH sitting there to cover the shortfall on paper.

WHERE TO PUT THIS: this file needs to physically exist in every repo
whose service will call it -- Railway services don't share a
filesystem. Right now that's just the `refractions` repo (alongside
base_buy.py). If/when you wire this into mojo_hawk.py, copy this same
file into the `mojohawk` repo too.

The actual on-chain conversion call mirrors base_buy.py's documented
account.swap(AccountSwapOptions(...)) pattern -- verify the exact
parameter names (from_token/to_token/amount, whatever it actually is)
against your real, working base_buy.py before trusting this in
production; it's written from the shape you described, not your literal
source.
"""
import os
import requests
from web3 import Web3

RPC_URL = os.environ.get("RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

USDC_ADDRESS = Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
WETH_ADDRESS = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
MIN_ETH_RESERVE_ETH = float(os.environ.get("MIN_ETH_RESERVE_ETH", "0.002"))

ERC20_BALANCE_ABI = [
    {"inputs": [{"type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]


def get_eth_balance(address: str) -> float:
    wei = w3.eth.get_balance(Web3.to_checksum_address(address))
    return wei / 1e18


def get_usdc_balance(address: str) -> float:
    contract = w3.eth.contract(address=USDC_ADDRESS, abi=ERC20_BALANCE_ABI)
    raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    return raw / 1e6  # USDC uses 6 decimals


def get_eth_price_usd() -> float:
    """ETH/USD off the deepest WETH pool on Base via DexScreener --
    reuses an API you're already calling elsewhere, no new dependency."""
    resp = requests.get(f"https://api.dexscreener.com/latest/dex/tokens/{WETH_ADDRESS}", timeout=15)
    resp.raise_for_status()
    pairs = resp.json().get("pairs") or []
    if not pairs:
        raise RuntimeError("could not fetch ETH price: no WETH pairs returned")
    best = max(pairs, key=lambda p: (p.get("liquidity", {}) or {}).get("usd", 0) or 0)
    return float(best["priceUsd"])


def quote_currency_from_pair(pair: dict):
    """
    Given a DexScreener pair object, returns "ETH" or "USDC" depending on
    which side the target token is quoted against, or None if it's quoted
    against something else entirely (this bot only holds ETH and USDC, so
    treat None as "skip the funding check, can't help with this one").
    """
    quote_symbol = ((pair.get("quoteToken") or {}).get("symbol") or "").upper()
    if quote_symbol in ("WETH", "ETH"):
        return "ETH"
    if quote_symbol == "USDC":
        return "USDC"
    return None


def ensure_funded(account, wallet_address: str, needed_currency: str, usd_amount: float) -> dict:
    """
    account: the CDP SDK account/wallet object -- the same one execute_buy
             already uses for account.swap(...).
    needed_currency: "ETH" or "USDC", whichever the target pair needs.
    usd_amount: how much (in USD) the upcoming buy needs in that currency.

    Returns:
      {"ok": True,  "swapped": bool, "swap_usd": float}
      {"ok": False, "reason": str}
    """
    if needed_currency not in ("ETH", "USDC"):
        return {"ok": False, "reason": f"unsupported currency: {needed_currency}"}

    eth_balance = get_eth_balance(wallet_address)
    usdc_balance = get_usdc_balance(wallet_address)
    eth_price = get_eth_price_usd()
    eth_balance_usd = eth_balance * eth_price

    have_usd = eth_balance_usd if needed_currency == "ETH" else usdc_balance
    if have_usd >= usd_amount:
        return {"ok": True, "swapped": False, "swap_usd": 0.0}

    shortfall_usd = usd_amount - have_usd
    other_currency = "USDC" if needed_currency == "ETH" else "ETH"

    if other_currency == "ETH":
        spendable_eth = max(0.0, eth_balance - MIN_ETH_RESERVE_ETH)
        max_swappable_usd = spendable_eth * eth_price
    else:
        max_swappable_usd = usdc_balance

    if max_swappable_usd < shortfall_usd:
        return {
            "ok": False,
            "reason": (
                f"insufficient combined balance: need ${shortfall_usd:.2f} more {needed_currency}, "
                f"only ${max_swappable_usd:.2f} of {other_currency} available after the "
                f"{MIN_ETH_RESERVE_ETH} ETH gas reserve"
            ),
        }

    # --- perform the conversion swap ---
    # TODO: verify this against base_buy.py's actual working call. Written
    # from the documented account.swap(AccountSwapOptions(...)) shape.
    from cdp import AccountSwapOptions  # adjust import path to match base_buy.py

    swap_result = account.swap(AccountSwapOptions(
        from_token=other_currency,
        to_token=needed_currency,
        amount_usd=shortfall_usd,
    ))

    return {"ok": True, "swapped": True, "swap_usd": shortfall_usd, "swap_result": swap_result}