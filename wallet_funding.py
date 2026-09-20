"""
wallet_funding.py

Shared, top-level funding check that sits in front of a buy: given the
currency a target pool actually needs (ETH or USDC), checks current
wallet balances and, if short, converts enough of the other currency to
cover it -- using the same create_swap_quote()/.execute() pattern
base_buy.py already uses for the buy itself, on the same CDP client
already open in the caller (no separate connection).

Gas on Base is always paid in ETH, so MIN_ETH_RESERVE_ETH is a hard
floor that's never swapped away, even when there's technically "enough"
ETH on paper to cover a shortfall.

WHERE TO PUT THIS: needs to physically exist in every repo whose service
calls it -- Railway services don't share a filesystem. Right now that's
the `refractions` repo, alongside base_buy.py (which imports this).

The balance-check functions below are plain Web3 RPC calls, independent
of cdp_utils.py. The currency constants (ETH_NATIVE, USDC_BASE,
USDC_DECIMALS) are imported directly from cdp_utils -- the same names
base_buy.py already uses -- so this stays correct even if those values
ever change, without needing to know what they currently are.
"""
import os
from web3 import Web3

from cdp_utils import ETH_NATIVE, USDC_BASE, USDC_DECIMALS

RPC_URL = os.environ.get("RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

MIN_ETH_RESERVE_ETH = float(os.environ.get("MIN_ETH_RESERVE_ETH", "0.002"))

ERC20_BALANCE_ABI = [
    {"inputs": [{"type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
]


def get_eth_balance(address: str) -> float:
    wei = w3.eth.get_balance(Web3.to_checksum_address(address))
    return wei / 1e18


def get_usdc_balance(address: str) -> float:
    contract = w3.eth.contract(address=Web3.to_checksum_address(USDC_BASE), abi=ERC20_BALANCE_ABI)
    raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    return raw / (10 ** USDC_DECIMALS)


async def ensure_funded(api_clients, wallet_addr: str, needed_currency: str, usd_amount: float, eth_usd_price: float) -> dict:
    """
    api_clients: cdp.api_clients from an already-open CdpClient (the same
                 one the caller's buy swap will use -- no new connection
                 is opened here).
    wallet_addr: BASE_SNIPER_WALLET_ADDRESS.
    needed_currency: "ETH" or "USDC" -- whichever the target pool needs.
    usd_amount: how much (in USD) the upcoming buy needs in that currency.
    eth_usd_price: pass in the already-fetched price (get_eth_usd_price()
                   from cdp_utils) rather than re-fetching here.

    Returns:
      {"ok": True,  "swapped": bool, "swap_usd": float}
      {"ok": False, "reason": str}
    """
    if needed_currency not in ("ETH", "USDC"):
        return {"ok": False, "reason": f"unsupported currency: {needed_currency}"}

    eth_balance = get_eth_balance(wallet_addr)
    usdc_balance = get_usdc_balance(wallet_addr)
    eth_balance_usd = eth_balance * eth_usd_price

    have_usd = eth_balance_usd if needed_currency == "ETH" else usdc_balance
    if have_usd >= usd_amount:
        return {"ok": True, "swapped": False, "swap_usd": 0.0}

    shortfall_usd = usd_amount - have_usd
    other_currency = "USDC" if needed_currency == "ETH" else "ETH"

    if other_currency == "ETH":
        spendable_eth = max(0.0, eth_balance - MIN_ETH_RESERVE_ETH)
        max_swappable_usd = spendable_eth * eth_usd_price
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

    # --- perform the conversion swap, same call shape as the buy itself ---
    from cdp.actions.evm.swap.create_swap_quote import create_swap_quote

    if other_currency == "USDC":
        from_amount = str(int(shortfall_usd * (10 ** USDC_DECIMALS)))
        from_token = USDC_BASE
        to_token = ETH_NATIVE
    else:
        eth_to_swap = shortfall_usd / eth_usd_price
        from_amount = str(int(eth_to_swap * 1e18))
        from_token = ETH_NATIVE
        to_token = USDC_BASE

    swap_quote = await create_swap_quote(
        api_clients=api_clients,
        from_token=from_token,
        to_token=to_token,
        from_amount=from_amount,
        network="base",
        taker=wallet_addr,
        slippage_bps=500,
    )

    if not swap_quote.liquidity_available:
        return {"ok": False, "reason": f"no liquidity to convert {other_currency} -> {needed_currency}"}

    await swap_quote.execute()

    return {"ok": True, "swapped": True, "swap_usd": shortfall_usd}
