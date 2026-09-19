# Refraction scanner — deployment notes (v2)

## The pipeline, step by step

Every candidate contract runs through all four checks; which ones actually
block a buy is controlled per-step by env vars (default: steps 1–3 are
hard-required, step 4 is a bonus signal — see table below).

| # | Step | What it checks | Data source | Default |
|---|------|------|------|---------|
| 1 | **Interface match** | Contract bytecode contains every function selector for *either* the Synthetix StakingRewards pattern *or* the full ERC-4626 vault pattern (deposit/mint/withdraw/redeem lifecycle) | Base RPC (free), with EIP-1967 proxy resolution | **Required** |
| 2 | **Holder concentration** | Top holder is a contract (not a wallet) and holds 30–70% of supply | Etherscan Pro `topholders` (chainid=8453) — needs `ETHERSCAN_API_KEY` | **Required** |
| 3 | **Reward token** | The contract's `rewardsToken()`/`rewardToken()` points at USDC, WETH, or cbBTC on Base | Base RPC (free) | **Required** |
| 4 | **Aerodrome gauge** | Registered as a gauge in Aerodrome's live Voter contract (`isGauge()`) | Base RPC (free) | **Bonus** (off by default) |

Step 4 defaults off because it's one specific sub-pattern — not every
refraction token will be an Aerodrome gauge specifically — so it's
reported but doesn't block a buy unless you set
`REFRACTION_REQUIRE_AERODROME_GAUGE=1`.

**None of this is a securities-law determination.** It confirms code
shape and on-chain facts — not distribution history, marketing, or who
actually controls reward funding, which is what an actual Howey analysis
turns on. Treat a pass as "matches the pattern you're looking for," not
"cleared by regulators."

## Why bytecode scanning, not calling, for step 1

The original version of this check trial-called each function. That
works fine for view functions but is unreliable for `stake()` /
`deposit()` / `withdraw()`: a simulated call to them almost always
reverts regardless of whether the function exists, because they try to
move tokens from an account with no real balance or approval. Scanning
the deployed bytecode for each function's 4-byte selector sidesteps that
— it's how bytecode-fingerprinting tools generally answer "does this
contract implement function X" without needing real state. If the
contract is an EIP-1967 proxy, the check follows it to the implementation
address first, since a thin proxy's own bytecode won't show the real
function set.

## Files

| File | Purpose |
|---|---|
| `refraction_check.py` | The 4-step pipeline, with per-step env toggles |
| `refraction_holders.py` | Etherscan/Basescan Pro top-holder lookup |
| `refraction_scanner.py` | Railway worker — polls DexScreener, runs the pipeline, buys, alerts |
| `refraction_discord_check_command.py` | Snippet to merge into `mojohawk_discord_bot.py` for manual `/check` |

## Integration TODOs

1. **`base_buy.py` needs a callable `execute_buy(token_address, usd_amount) -> dict`.**
   If it's currently CLI-only, pull the swap logic into a plain function
   the scanner can import.
2. **Get an Etherscan API key on a Standard (Pro) plan or above** — the
   `topholders` endpoint requires it. Set it as `ETHERSCAN_API_KEY`. The
   same key works across all of Etherscan's 60+ supported chains (pass
   `chainid` per request), so it's reusable well beyond this bot if you
   want other Pro-tier data elsewhere in the stack.
3. **Merge `refraction_discord_check_command.py`** into your actual bot
   file — assumes a `bot` variable and command tree already exist.
4. **Create a Discord webhook** in the trading channel and set it as
   `DISCORD_WEBHOOK_URL`.

## Railway deployment

New worker service in the `terrific-perception` project:

- Start command: `python refraction_scanner.py`
- Connect it to the same Redis instance the rest of the stack uses
- Env vars:

| Var | Default | Notes |
|---|---|---|
| `RPC_URL` | `https://mainnet.base.org` | |
| `REDIS_URL` | — | required |
| `ETHERSCAN_API_KEY` | — | required for step 2 (Pro plan) |
| `DISCORD_WEBHOOK_URL` | — | required for alerts |
| `REFRACTION_BUY_USD` | `10` | |
| `REFRACTION_MAX_BUYS_PER_DAY` | `3` | resets at UTC midnight |
| `REFRACTION_MIN_LIQUIDITY_USD` | `5000` | set to `0` to disable |
| `POLL_INTERVAL_SECONDS` | `120` | matches `poller.py`'s 2-min cadence |
| `REFRACTION_REQUIRE_INTERFACE` | `1` | set `0` to make step 1 bonus-only |
| `REFRACTION_REQUIRE_HOLDER_CONCENTRATION` | `1` | set `0` to make step 2 bonus-only |
| `REFRACTION_REQUIRE_REWARD_TOKEN` | `1` | set `0` to make step 3 bonus-only |
| `REFRACTION_REQUIRE_AERODROME_GAUGE` | `0` | set `1` to make step 4 required |
| `REFRACTION_MIN_HOLDER_PCT` | `30` | |
| `REFRACTION_MAX_HOLDER_PCT` | `70` | |

`requirements.txt` additions: `web3`, `redis`, `requests` (you already
have `discord.py` and the CDP SDK from the rest of the stack).

## Practical note on hard-AND gating

Stacking three independent, fairly rare on-chain signals (exact interface
match + specific holder concentration band + specific reward asset) as a
hard requirement means matches will likely be infrequent — that's the
tradeoff of tightening it this much. If the bot goes quiet for a long
stretch, that's the gate working as configured, not necessarily broken.
The per-step toggles above are there so you can loosen one at a time
without touching code if you want to see how much each one is filtering.
