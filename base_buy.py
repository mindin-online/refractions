"""  # v2.1 — added execute_buy() for automated callers; CLI arg-parsing
# moved under __main__ so the module is safely importable (previously it
# ran at module scope and would sys.exit(1) on import with no argv).
base_buy.py — Manual DEX Buy Tool (Base Chain)
Supports ETH and USDC pools. Auto-detects quote token.

Usage:
  python base_buy.py SYMBOL              # 0.009 ETH default
  python base_buy.py SYMBOL 0.02         # fixed ETH amount
  python base_buy.py SYMBOL 50%          # 50% of wallet ETH
  python base_buy.py 0xCONTRACT         # buy by contract address
  python base_buy.py 0xCONTRACT 0.02   # buy contract with amount

Programmatic usage (e.g. from refraction_scanner.py):
  import asyncio
  from base_buy import execute_buy
  result = asyncio.run(execute_buy(token_address, usd_amount))
"""
import os, sys, asyncio, logging, smtplib, requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "base_buy.log")),
    ]
)
log = logging.getLogger(__name__)

# ── Import shared utils ────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp_utils import (
    ETH_NATIVE, WETH_BASE, USDC_BASE, USDC_DECIMALS, PERMIT2,
    DS_HEADERS, get_cdp_config, patch_cdp_sdk,
    get_token_balance, get_wallet_tokens,
    get_token_price, get_eth_usd_price
)

patch_cdp_sdk()

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_ETH     = 0.009
MIN_LIQ         = 50_000
GMAIL_ADDRESS   = os.getenv("GMAIL_ADDRESS", "")
GMAIL_APP_PW    = os.getenv("GMAIL_APP_PW", "")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL", "")

# ── Telegram ──────────────────────────────────────────────────────────────────
try:
    import tg
    _tg = tg
except ImportError:
    _tg = None

def tg_send(msg):
    if _tg:
        try: _tg.send(msg)
        except Exception: pass

# ── DexScreener ───────────────────────────────────────────────────────────────
def search_pools(symbol: str = None, contract: str = None) -> list:
    """Search DexScreener for token pools on Base."""
    try:
        if contract:
            r = requests.get(
                f"https://api.dexscreener.com/latest/dex/tokens/{contract}",
                headers=DS_HEADERS, timeout=15)
            data = r.json()
            pairs = data if isinstance(data, list) else data.get("pairs", [])
            pairs = [p for p in pairs
                     if p.get("chainId") == "base"
                     and p.get("baseToken", {}).get("address", "").lower() == contract.lower()]
        else:
            r = requests.get(
                f"https://api.dexscreener.com/latest/dex/search?q={symbol}",
                headers=DS_HEADERS, timeout=15)
            pairs = r.json().get("pairs", [])
            pairs = [p for p in pairs
                     if p.get("chainId") == "base"
                     and p.get("baseToken", {}).get("symbol", "").upper() == symbol]

        result = []
        for p in pairs:
            result.append({
                "token_address": p.get("baseToken", {}).get("address", ""),
                "token_symbol":  p.get("baseToken", {}).get("symbol", symbol or ""),
                "token_name":    p.get("baseToken", {}).get("name", ""),
                "quote_symbol":  p.get("quoteToken", {}).get("symbol", ""),
                "dex":           p.get("dexId", ""),
                "liquidity_usd": float(p.get("liquidity", {}).get("usd", 0) or 0),
                "vol_1h":        float(p.get("volume", {}).get("h1", 0) or 0),
                "change_1h":     float(p.get("priceChange", {}).get("h1", 0) or 0),
                "price_usd":     float(p.get("priceUsd", 0) or 0),
            })
        return sorted(result, key=lambda x: x["liquidity_usd"], reverse=True)
    except Exception as e:
        log.error(f"DexScreener error: {e}")
        return []


def select_best_pool(pools: list, bypass_liq: bool = False) -> dict | None:
    """Select best pool — ETH preferred, USDC fallback."""
    eth_pools  = [p for p in pools if "ETH" in p["quote_symbol"].upper()]
    usdc_pools = [p for p in pools if p["quote_symbol"].upper() in ("USDC", "USDbC")]

    if not bypass_liq:
        eth_pools  = [p for p in eth_pools  if p["liquidity_usd"] >= MIN_LIQ]
        usdc_pools = [p for p in usdc_pools if p["liquidity_usd"] >= MIN_LIQ]

    if eth_pools:
        best = max(eth_pools, key=lambda x: x["liquidity_usd"])
        best["use_usdc"] = False
        return best
    if usdc_pools:
        best = max(usdc_pools, key=lambda x: x["liquidity_usd"])
        best["use_usdc"] = True
        print(f"  No ETH pool — using USDC pool ({best['dex']})")
        return best

    print(f"  No ETH or USDC pool found")
    avail = ', '.join(set(p['quote_symbol'] for p in pools))
    if avail:
        print(f"  Available pairs: {avail}")
    return None


# ── Automated entry point (NEW — used by refraction_scanner.py etc.) ────────
async def execute_buy(token_address: str, usd_amount: float) -> dict:
    """
    Programmatic buy entry point for automated callers. USD-denominated,
    unlike the CLI tool (which is ETH/percentage-denominated) -- this is
    an additive code path, it doesn't touch main() or any CLI parsing.

    Auto-detects the pool's quote currency the same way the CLI does
    (search_pools + select_best_pool), uses wallet_funding.ensure_funded()
    to convert currencies first if the wallet's short on whichever side
    is needed, then executes the buy with the same create_swap_quote()
    pattern the CLI path uses.

    Returns: {"tx_hash": str, "tokens_received": float, "spend_usd": float}
    Raises RuntimeError on failure -- callers should catch it.
    """
    from cdp import CdpClient
    from cdp.actions.evm.swap.create_swap_quote import create_swap_quote
    from wallet_funding import ensure_funded

    pools = search_pools(contract=token_address)
    pool = select_best_pool(pools, bypass_liq=True)  # caller already checked liquidity
    if not pool:
        raise RuntimeError(f"no pool found for {token_address}")

    symbol = pool["token_symbol"]
    use_usdc = pool.get("use_usdc", False)
    eth_usd = get_eth_usd_price()

    key_id      = os.getenv("CDP_API_KEY_ID", "")
    key_sec     = os.getenv("CDP_API_KEY_SECRET", "")
    wal_sec     = os.getenv("CDP_WALLET_SECRET", "")
    wallet_addr = os.getenv("BASE_SNIPER_WALLET_ADDRESS", "")

    async with CdpClient(api_key_id=key_id, api_key_secret=key_sec, wallet_secret=wal_sec) as cdp:
        needed_currency = "USDC" if use_usdc else "ETH"
        funding = await ensure_funded(cdp.api_clients, wallet_addr, needed_currency, usd_amount, eth_usd)
        if not funding["ok"]:
            raise RuntimeError(f"funding check failed: {funding['reason']}")

        if use_usdc:
            from_amount = str(int(usd_amount * 10 ** USDC_DECIMALS))
            from_token  = USDC_BASE
        else:
            eth_amount  = usd_amount / eth_usd
            from_amount = str(int(eth_amount * 1e18))
            from_token  = ETH_NATIVE

        swap_quote = await create_swap_quote(
            api_clients=cdp.api_clients,
            from_token=from_token,
            to_token=token_address,
            from_amount=from_amount,
            network="base",
            taker=wallet_addr,
            slippage_bps=500,
        )

        if not swap_quote.liquidity_available:
            raise RuntimeError("no liquidity available for this swap")

        _result = await swap_quote.execute()
        tx_hash = (getattr(_result, "transaction_hash", None)
                   or getattr(_result, "tx_hash", None)
                   or str(_result))

        to_amt = int(getattr(swap_quote, "to_amount", 0) or 0)
        tokens_received = to_amt / (10 ** 18)

        log.info(f"AUTO-BUY | {symbol} | ${usd_amount:.2f} | {tokens_received:.4f} tokens | tx={tx_hash} | "
                 f"funded_via_conversion={funding['swapped']}")

        return {"tx_hash": tx_hash, "tokens_received": tokens_received, "spend_usd": usd_amount}


# ── CLI entry point (UNCHANGED logic, just now takes params instead of
#    reading module-level globals) ──────────────────────────────────────────
async def main(buy_contract, input_symbol, buy_eth, buy_pct):
    # Find pool
    if buy_contract:
        print(f"\n  Searching by contract: {buy_contract}...")
        pools = search_pools(contract=buy_contract)
        pool  = select_best_pool(pools, bypass_liq=True)
    else:
        print(f"\n  Searching DexScreener for: {input_symbol}...")
        pools = search_pools(symbol=input_symbol)
        pool  = select_best_pool(pools, bypass_liq=True)  # manual buy always bypasses liq filter

    if not pool:
        print(f"  No pool found for {input_symbol or buy_contract}")
        sys.exit(1)

    token_address = pool["token_address"]
    symbol        = pool["token_symbol"]
    use_usdc      = pool.get("use_usdc", False)
    eth_usd       = get_eth_usd_price()

    print(f"  Token:  {symbol} ({token_address})")
    print(f"  Pool:   {pool['dex']} | Liq: ${pool['liquidity_usd']:,.0f}")
    print(f"  Price:  ${pool['price_usd']:.8f}")
    print(f"  Quote:  {'USDC' if use_usdc else 'ETH'}")

    # Resolve buy amount
    if buy_pct is not None:
        try:
            from cdp import CdpClient
            async with CdpClient(
                api_key_id=os.getenv("CDP_API_KEY_ID",""),
                api_key_secret=os.getenv("CDP_API_KEY_SECRET",""),
                wallet_secret=os.getenv("CDP_WALLET_SECRET",""),
            ) as cdp:
                result = await cdp.evm.list_token_balances(
                    address=os.getenv("BASE_SNIPER_WALLET_ADDRESS",""), network="base")
                for bal in result.balances:
                    if bal.token.symbol == "ETH":
                        eth_bal = bal.amount.amount / 1e18
                        buy_eth = round(eth_bal * (buy_pct / 100), 6)
                        print(f"  Wallet: {eth_bal:.6f} ETH → buying {buy_pct:.0f}% = {buy_eth:.6f} ETH")
                        break
        except Exception as e:
            print(f"  Could not fetch wallet balance: {e}")
            sys.exit(1)

    if not buy_eth or buy_eth <= 0:
        print("  Invalid buy amount")
        sys.exit(1)

    # Execute
    try:
        from cdp import CdpClient
        from cdp.actions.evm.swap.create_swap_quote import create_swap_quote
        from cdp.evm_transaction_types import TransactionRequestEIP1559

        key_id      = os.getenv("CDP_API_KEY_ID", "")
        key_sec     = os.getenv("CDP_API_KEY_SECRET", "")
        wal_sec     = os.getenv("CDP_WALLET_SECRET", "")
        wallet_addr = os.getenv("BASE_SNIPER_WALLET_ADDRESS", "")
        async with CdpClient(
            api_key_id=key_id,
            api_key_secret=key_sec,
            wallet_secret=wal_sec,
        ) as cdp:
            account = await cdp.evm.get_or_create_account(name="base-sniper")

            if use_usdc:
                usdc_amount = buy_eth * eth_usd
                from_amount = str(int(usdc_amount * 10**USDC_DECIMALS))
                from_token  = USDC_BASE
                print(f"\n  Buying with ${usdc_amount:.2f} USDC...")
                # CDP SDK handles Permit2 approval internally for ERC20 swaps
            else:
                from_amount = str(int(buy_eth * 1e18))
                from_token  = ETH_NATIVE
                print(f"\n  Buying with {buy_eth} ETH...")

            swap_quote = await create_swap_quote(
                api_clients=cdp.api_clients,
                from_token=from_token,
                to_token=token_address,
                from_amount=from_amount,
                network="base",
                taker=wallet_addr,
                slippage_bps=500,
            )

            if not swap_quote.liquidity_available:
                print(f"  No liquidity available")
                sys.exit(1)

            _result = await swap_quote.execute()
            tx_hash = (getattr(_result, "transaction_hash", None)
                       or getattr(_result, "tx_hash", None)
                       or str(_result))

            # Permit2 pre-approval for future sells
            try:
                spender_padded = PERMIT2[2:].lower().zfill(64)
                approve_data   = f"0x095ea7b3{spender_padded}{'f'*64}"
                approve_tx     = TransactionRequestEIP1559(
                    to=token_address, data=approve_data, value=0)
                await account.send_transaction(transaction=approve_tx, network="base")
                import asyncio as _a2; await _a2.sleep(2)
                print(f"  Permit2 pre-approved for future sells")
            except Exception:
                pass

            # Calculate received
            to_amt          = int(getattr(swap_quote, "to_amount", 0) or 0)
            tokens_received = to_amt / (10 ** 18)
            spend_str       = f"${usdc_amount:.2f} USDC" if use_usdc else f"{buy_eth:.6f} ETH (${buy_eth*eth_usd:.2f})"

            print(f"\n  {'='*52}")
            print(f"  BUY EXECUTED")
            print(f"  {'='*52}")
            print(f"  Spent:    {spend_str}")
            print(f"  Received: {tokens_received:,.4f} {symbol}")
            print(f"  TX: https://basescan.org/tx/{tx_hash}")

            log.info(f"BUY | {symbol} | {spend_str} | {tokens_received:.4f} tokens | tx={tx_hash}")

            tg_send(
                f"🟢 <b>BUY — {symbol}</b>\n"
                f"💸 <b>Spent:</b> {spend_str}\n"
                f"🪙 <b>Received:</b> {tokens_received:,.2f} {symbol}\n"
                f"📈 <b>Price:</b> ${pool['price_usd']:.8f} | 1h: {pool['change_1h']:+.1f}%\n"
                f"⚡ <b>DEX:</b> {pool['dex']} | 💧 ${pool['liquidity_usd']/1000:.0f}k liq\n"
                f"🔗 <a href='https://basescan.org/tx/{tx_hash}'>View TX</a>"
            )

            try:
                msg = MIMEMultipart()
                msg["From"]    = GMAIL_ADDRESS
                msg["To"]      = RECIPIENT_EMAIL
                msg["Subject"] = f"Buy: {symbol} — {spend_str}"
                msg.attach(MIMEText(
                    f"<h3>Buy Executed — {symbol}</h3>"
                    f"<b>Spent:</b> {spend_str}<br>"
                    f"<b>Received:</b> {tokens_received:,.2f} {symbol}<br>"
                    f"<b>Price:</b> ${pool['price_usd']:.8f}<br>"
                    f"<b>TX:</b> <a href='https://basescan.org/tx/{tx_hash}'>{tx_hash[:20]}...</a>",
                    "html"))
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                    s.login(GMAIL_ADDRESS, GMAIL_APP_PW)
                    s.send_message(msg)
            except Exception:
                pass

    except Exception as e:
        print(f"  Buy failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("Usage: base_buy.py SYMBOL_OR_CONTRACT [eth_amount_or_%]")
        sys.exit(1)

    _raw_arg      = args[0]
    _buy_contract = _raw_arg if (_raw_arg.startswith("0x") and len(_raw_arg) == 42) else None
    _cli_symbol   = _raw_arg if _buy_contract else _raw_arg.upper()

    _buy_eth = DEFAULT_ETH
    _buy_pct = None
    if len(args) > 1:
        _amt = args[1]
        if _amt.endswith("%"):
            _buy_pct = float(_amt[:-1])
            _buy_eth = None
        else:
            _buy_eth = float(_amt)

    asyncio.run(main(_buy_contract, _cli_symbol, _buy_eth, _buy_pct))
