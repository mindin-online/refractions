"""
refraction_payouts.py

"Does it ACTUALLY pay?" -- proof from on-chain logs, not from what the code
or the marketing says.

The research behind this: most "earn cbBTC/USDC" tokens on Base are dormant,
micro-cap, or pay by off-contract airdrop. BasePrinter, for example, has the
right code, tens of thousands of holders, and no current activity. So a code
match alone is never treated as proof.

WHAT IT CHECKS (read-only, eth_getLogs, walking BACKWARD from the latest
block so recent evidence is found first and healthy payers exit early):

  1. ERC-20 payouts: Transfer logs of the candidate reward assets
     (USDC / WETH / cbBTC, or the asset the contract names) FROM the payer
     contract(s) to distinct recipients. Counts distinct recipients,
     distinct active days, and how concentrated the money is (one wallet
     receiving nearly everything is not a payout to holders).
  2. Event evidence: Claim / DividendWithdrawn / RewardPaid events. These
     are the only trace of native-ETH payouts, but an event can be emitted
     without value moving, so on their own they are "events_only", a weaker
     grade than a verified ERC-20 transfer.
  3. Who triggers it: the sender of a sample of payout transactions.
       automatic    payouts are pushed to holders in transactions started by
                    many different people (e.g. ordinary swaps)
       pull_claims  holders claim for themselves (normal for staking pools)
       manual_push  one or two senders push payouts -- a person is doing it
       unknown      couldn't tell

PROOF GRADES
  strong       enough distinct recipients, over enough days, with ERC-20
               transfers actually observed, and the money not concentrated.
  events_only  claim/payout events from enough recipients but no matching
               ERC-20 transfers (native ETH, or unverifiable).
  none         scanned the window; no evidence.
  unknown      the RPC could not serve the scan.

LIMITS. The window is bounded (default ~3 days) to keep RPC cost sane, so a
token that pays rarely can read as "none". Public RPCs cap eth_getLogs
ranges; chunks that fail are skipped, and if none succeed the result is
"unknown", never "none".
"""
import os
from web3 import Web3

try:
    from refraction_holders import KNOWN_POOL_SINGLETONS, BURN_ADDRESSES
except Exception:  # keep this module importable on its own
    KNOWN_POOL_SINGLETONS, BURN_ADDRESSES = {}, {"0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead"}

WINDOW_BLOCKS = int(os.environ.get("REFRACTION_PAYOUT_WINDOW_BLOCKS", "129600"))   # ~3 days on Base (2s blocks)
CHUNK_SIZE = int(os.environ.get("REFRACTION_PAYOUT_CHUNK_SIZE", "2000"))
MIN_RECIPIENTS = int(os.environ.get("REFRACTION_PAYOUT_MIN_RECIPIENTS", "10"))
MIN_ACTIVE_DAYS = int(os.environ.get("REFRACTION_PAYOUT_MIN_ACTIVE_DAYS", "2"))
MAX_TOP_SHARE = float(os.environ.get("REFRACTION_PAYOUT_MAX_TOP_SHARE", "0.8"))
MAX_RPC_CALLS = int(os.environ.get("REFRACTION_PAYOUT_MAX_RPC_CALLS", "160"))
SAMPLE_TXS = int(os.environ.get("REFRACTION_PAYOUT_SAMPLE_TXS", "12"))
BLOCKS_PER_DAY = 43200

TRANSFER_TOPIC = "0x" + bytes(Web3.keccak(text="Transfer(address,address,uint256)")).hex()
EVENT_TOPICS = [
    "0x" + bytes(Web3.keccak(text="Claim(address,uint256,bool)")).hex(),
    "0x" + bytes(Web3.keccak(text="DividendWithdrawn(address,uint256)")).hex(),
    "0x" + bytes(Web3.keccak(text="RewardPaid(address,uint256)")).hex(),
]
CLAIM_TOPIC = EVENT_TOPICS[0]


def _pad(addr: str) -> str:
    return "0x" + "00" * 12 + addr[2:].lower()


def _topic_addr(topic) -> str:
    return Web3.to_checksum_address("0x" + bytes(topic)[-20:].hex())


def _word(data, i):
    raw = bytes(data)
    return int.from_bytes(raw[i * 32:(i + 1) * 32], "big") if len(raw) >= (i + 1) * 32 else None


def verify_payouts(w3, token: str, payers: list, candidate_assets: dict, exclude: list = None,
                   reflection_hint: bool = False) -> dict:
    """
    token:            the token address
    payers:           addresses that would be sending payouts (tracker,
                      staking contract, and/or the token itself)
    candidate_assets: {address: label} of ERC-20 reward assets to look for
    exclude:          extra addresses never counted as holder recipients
                      (the liquidity pool, etc.)
    """
    out = {
        "ran": False, "proof": "unknown", "reason": "", "payers": [], "scanned_blocks": 0,
        "erc20": {"asset": None, "label": None, "recipients": 0, "active_days": 0,
                  "transfers": 0, "top_share": None, "last_age_blocks": None},
        "events": {"count": 0, "recipients": 0, "auto_claims": 0, "last_age_blocks": None},
        "trigger": {"verdict": "unknown", "sampled": 0, "distinct_senders": 0, "mode": None},
        "reward_asset_observed": None,
    }
    token = Web3.to_checksum_address(token)
    payer_set = []
    for p in payers:
        p = Web3.to_checksum_address(p)
        if p not in payer_set:
            payer_set.append(p)
    out["payers"] = payer_set
    if not payer_set:
        out["reason"] = "no payer address to scan"
        return out

    assets = [Web3.to_checksum_address(a) for a in candidate_assets]
    never = {a.lower() for a in payer_set} | {token.lower()} | {a.lower() for a in BURN_ADDRESSES} \
        | {a.lower() for a in KNOWN_POOL_SINGLETONS} | {a.lower() for a in (exclude or [])}

    try:
        latest = w3.eth.block_number
    except Exception as e:
        out["reason"] = f"could not read block number: {e}"
        return out

    # per-asset aggregation
    per_asset = {}   # asset -> {"recips": {addr: amount}, "days": set, "n": int, "last": block}
    tx_recipients = {}  # txhash -> set(recipient)
    ev_recips, ev_days, ev_count, ev_auto, ev_last = set(), set(), 0, 0, None
    ev_tx = {}
    calls, ok_chunks = 0, 0
    end = latest
    stop_early = False

    while end > max(0, latest - WINDOW_BLOCKS) and calls < MAX_RPC_CALLS and not stop_early:
        start = max(0, end - CHUNK_SIZE + 1)
        # (1) ERC-20 transfers from payers
        if assets:
            calls += 1
            try:
                logs = w3.eth.get_logs({
                    "address": assets,
                    "topics": [TRANSFER_TOPIC, [_pad(p) for p in payer_set]],
                    "fromBlock": start, "toBlock": end,
                })
                ok_chunks += 1
                for lg in logs:
                    try:
                        recip = _topic_addr(lg["topics"][2])
                        amt = int.from_bytes(bytes(lg["data"]), "big")
                    except Exception:
                        continue
                    if recip.lower() in never:
                        continue
                    a = Web3.to_checksum_address(lg["address"])
                    d = per_asset.setdefault(a, {"recips": {}, "days": set(), "n": 0, "last": None})
                    d["recips"][recip] = d["recips"].get(recip, 0) + amt
                    d["days"].add((latest - lg["blockNumber"]) // BLOCKS_PER_DAY)
                    d["n"] += 1
                    d["last"] = max(d["last"] or 0, lg["blockNumber"])
                    tx_recipients.setdefault(lg["transactionHash"], set()).add(recip)
            except Exception:
                pass
        # (2) claim / payout events
        calls += 1
        try:
            evs = w3.eth.get_logs({
                "address": payer_set + ([token] if token not in payer_set else []),
                "topics": [EVENT_TOPICS],
                "fromBlock": start, "toBlock": end,
            })
            ok_chunks += 1
            for lg in evs:
                t0 = "0x" + bytes(lg["topics"][0]).hex()
                try:
                    recip = _topic_addr(lg["topics"][1]) if len(lg["topics"]) >= 2 else \
                        Web3.to_checksum_address("0x" + bytes(lg["data"])[12:32].hex())
                except Exception:
                    continue
                if recip.lower() in never:
                    continue
                ev_count += 1
                ev_recips.add(recip)
                ev_days.add((latest - lg["blockNumber"]) // BLOCKS_PER_DAY)
                ev_last = max(ev_last or 0, lg["blockNumber"])
                ev_tx.setdefault(lg["transactionHash"], set()).add(recip)
                if t0 == CLAIM_TOPIC:
                    auto = int.from_bytes(bytes(lg["topics"][2]), "big") if len(lg["topics"]) >= 3 else _word(lg["data"], 2)
                    if auto:
                        ev_auto += 1
        except Exception:
            pass

        # early exit once there is plenty of proof
        for a, d in per_asset.items():
            if len(d["recips"]) >= 2 * MIN_RECIPIENTS and len(d["days"]) >= MIN_ACTIVE_DAYS:
                stop_early = True
        end = start - 1

    out["ran"] = True
    out["scanned_blocks"] = latest - end
    if ok_chunks == 0:
        out["proof"] = "unknown"
        out["reason"] = "RPC could not serve eth_getLogs for any chunk (range limits / rate limit)"
        return out

    # best asset = most distinct recipients
    best = None
    for a, d in per_asset.items():
        if best is None or len(d["recips"]) > len(per_asset[best]["recips"]):
            best = a
    if best:
        d = per_asset[best]
        total = sum(d["recips"].values()) or 1
        out["erc20"] = {
            "asset": best, "label": candidate_assets.get(best) or candidate_assets.get(best.lower()),
            "recipients": len(d["recips"]), "active_days": len(d["days"]), "transfers": d["n"],
            "top_share": max(d["recips"].values()) / total,
            "last_age_blocks": latest - d["last"] if d["last"] else None,
        }
        out["reward_asset_observed"] = {"address": best, "label": out["erc20"]["label"]}
    out["events"] = {"count": ev_count, "recipients": len(ev_recips), "auto_claims": ev_auto,
                     "last_age_blocks": (latest - ev_last) if ev_last else None}

    # who triggers payouts? sample transactions
    all_tx = dict(tx_recipients)
    for h, r in ev_tx.items():
        all_tx.setdefault(h, set()).update(r)
    hashes = list(all_tx.keys())
    if len(hashes) > SAMPLE_TXS:
        step = len(hashes) / SAMPLE_TXS
        hashes = [hashes[int(i * step)] for i in range(SAMPLE_TXS)]
    senders, push, pull = set(), 0, 0
    sampled = 0
    for h in hashes:
        try:
            tx = w3.eth.get_transaction(h)
            frm = Web3.to_checksum_address(tx["from"])
        except Exception:
            continue
        sampled += 1
        senders.add(frm)
        if frm in all_tx[h]:
            pull += 1
        else:
            push += 1
    if sampled:
        mode = "push" if push / sampled >= 0.6 else ("pull" if pull / sampled >= 0.6 else "mixed")
        if mode == "pull":
            verdict = "pull_claims"
        elif mode == "push":
            verdict = "automatic" if len(senders) >= 3 else "manual_push"
        else:
            verdict = "unknown"
        out["trigger"] = {"verdict": verdict, "sampled": sampled, "distinct_senders": len(senders), "mode": mode}

    e = out["erc20"]
    if (e["recipients"] >= MIN_RECIPIENTS and e["active_days"] >= MIN_ACTIVE_DAYS
            and (e["top_share"] or 0) <= MAX_TOP_SHARE):
        out["proof"] = "strong"
        out["reason"] = (f"{e['recipients']} distinct recipients over {e['active_days']} day(s) "
                         f"received {e['label'] or e['asset']}")
    elif len(ev_recips) >= MIN_RECIPIENTS:
        out["proof"] = "events_only"
        out["reason"] = (f"{len(ev_recips)} recipients in claim/payout events, but no matching ERC-20 "
                         f"transfers found (native ETH, or events that can't be verified)")
    elif e["recipients"] > 0:
        out["proof"] = "none"
        out["reason"] = (f"only {e['recipients']} recipient(s) over {e['active_days']} day(s) "
                         f"-- below the proof threshold")
    else:
        out["proof"] = "none"
        out["reason"] = f"no payouts observed in the last ~{(latest - end) // BLOCKS_PER_DAY or '<1'} day(s) scanned"
    return out


VAULT_ABI = [
    {"inputs": [{"type": "uint256"}], "name": "convertToAssets", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "stateMutability": "view", "type": "function"},
]


def verify_vault_yield(w3, vault: str, lookback_blocks: int = BLOCKS_PER_DAY) -> dict:
    """
    ERC-4626 vaults don't send payout transactions -- yield shows up as the
    share price rising. So the proof here is a share-price comparison now
    vs. ~a day ago (convertToAssets of one whole share).

    Two honest limits, which is why the best grade here is "drift_only":
      * reading state a day back needs an archive-capable RPC; ordinary
        public nodes often refuse. Then the result is "unknown", never a
        guess.
      * share price can be pushed up by a plain donation, so a rise proves
        the price moved, not that a strategy earned it.
    """
    out = {"ran": True, "proof": "unknown", "reason": "", "payers": [vault], "scanned_blocks": 0,
           "erc20": {"asset": None, "label": None, "recipients": 0, "active_days": 0, "transfers": 0,
                     "top_share": None, "last_age_blocks": None},
           "events": {"count": 0, "recipients": 0, "auto_claims": 0, "last_age_blocks": None},
           "trigger": {"verdict": "unknown", "sampled": 0, "distinct_senders": 0, "mode": None},
           "reward_asset_observed": None, "vault": {"drift_pct": None}}
    try:
        c = w3.eth.contract(address=Web3.to_checksum_address(vault), abi=VAULT_ABI)
        latest = w3.eth.block_number
        dec = c.functions.decimals().call()
        unit = 10 ** dec
        now_price = c.functions.convertToAssets(unit).call()
    except Exception as e:
        out["reason"] = f"could not read vault share price: {e}"
        return out
    try:
        then_price = c.functions.convertToAssets(unit).call(block_identifier=max(0, latest - lookback_blocks))
    except Exception as e:
        out["reason"] = f"RPC can't read historical state (needs an archive node): {e}"
        return out
    if then_price <= 0:
        out["reason"] = "share price was zero a day ago (vault too new)"
        return out
    drift = (now_price - then_price) / then_price * 100
    out["vault"]["drift_pct"] = drift
    out["scanned_blocks"] = lookback_blocks
    if drift > 0:
        out["proof"] = "drift_only"
        out["reason"] = f"share price up {drift:.4f}% over ~1 day (could be a donation, not earned yield)"
    else:
        out["proof"] = "none"
        out["reason"] = f"share price did not rise over ~1 day ({drift:.4f}%)"
    return out
