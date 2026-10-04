"""
refraction_discovery.py

More ways to FIND candidates -- the point of the "comb through more coins"
scan. The new-token feed and the 1-hour movers scan both sample young,
volatile tokens, which is exactly where legacy-style reward tokens are least
likely to be: the ones that still pay tend to be older and quietly active.
So this adds three different nets, run about once a day:

  1. KEYWORD SEARCH (DexScreener search, free, no key): tokens whose
     name/symbol uses the language these projects brand themselves with
     (reward, dividend, printer, BTC, USDC, ...). Low precision on its own
     -- it only decides what gets looked at; the on-chain checks decide
     what's real.
  2. ESTABLISHED & ACTIVE (GeckoTerminal pools by 24h volume): pools older
     than REFRACTION_DISC_MIN_AGE_DAYS with real, sustained volume -- the
     "already out there" population the new-token feed never shows.
  3. TRENDING (GeckoTerminal trending pools).

NOT BUILT, deliberately: CoinGecko / CoinMarketCap category pages. The
research found no "reflection"/"dividend" category on either (the nearest
CoinGecko ones are "rebase tokens" and "yield-bearing tokens", dominated by
unrelated designs), so they'd mostly add noise and need API keys.

Everything returned here is just candidate ADDRESSES; each one still goes
through the same staged evaluation as every other candidate.
"""
import os
import re
import requests
from datetime import datetime, timezone

DEX_SEARCH_URL = "https://api.dexscreener.com/latest/dex/search"
GECKO_POOLS_URL = "https://api.geckoterminal.com/api/v2/networks/base/pools"
GECKO_TRENDING_URL = "https://api.geckoterminal.com/api/v2/networks/base/trending_pools"

DEFAULT_KEYWORDS = "reward,rewards,dividend,reflect,reflection,printer,yield,btc,cbbtc,usdc,earn,passive,vault,staking"
KEYWORDS = [k.strip() for k in os.environ.get("REFRACTION_DISCOVERY_KEYWORDS", DEFAULT_KEYWORDS).split(",") if k.strip()]
MIN_LIQ = float(os.environ.get("REFRACTION_DISC_MIN_LIQUIDITY_USD", "5000"))
MIN_VOL = float(os.environ.get("REFRACTION_DISC_MIN_VOLUME_USD", "2000"))
MIN_AGE_DAYS = float(os.environ.get("REFRACTION_DISC_MIN_AGE_DAYS", "7"))
ESTABLISHED_PAGES = int(os.environ.get("REFRACTION_DISC_PAGES", "5"))
ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")

# Mainstream assets show up as the 'base token' of huge pools; never candidates.
SKIP = {a.lower() for a in (
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC
    "0x4200000000000000000000000000000000000006",  # WETH
    "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf",  # cbBTC
    "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA",  # USDbC
    "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",  # DAI
)}


def search_candidates(keywords=None, per_keyword_cap=15):
    out = []
    for kw in (keywords or KEYWORDS):
        try:
            resp = requests.get(DEX_SEARCH_URL, params={"q": kw}, timeout=15)
            resp.raise_for_status()
            pairs = resp.json().get("pairs") or []
        except Exception:
            continue
        n = 0
        for p in pairs:
            if p.get("chainId") != "base":
                continue
            addr = (p.get("baseToken") or {}).get("address") or ""
            liq = (p.get("liquidity") or {}).get("usd") or 0
            if not ADDR_RE.fullmatch(addr) or addr.lower() in SKIP or liq < MIN_LIQ:
                continue
            out.append({"token_address": addr, "why": f"search:{kw}", "liquidity_usd": liq,
                        "volume24h_usd": (p.get("volume") or {}).get("h24") or 0})
            n += 1
            if n >= per_keyword_cap:
                break
    return out


def _gecko_resolve(pool, included):
    tid = (pool.get("relationships") or {}).get("base_token", {}).get("data", {}).get("id")
    match = next((t for t in included if t.get("id") == tid), None)
    return (match or {}).get("attributes", {}).get("address")


def _age_days(attrs):
    s = attrs.get("pool_created_at")
    if not s:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(s.replace("Z", "+00:00"))).total_seconds() / 86400
    except Exception:
        return None


def established_candidates(pages=None, limit=40):
    rows = []
    for page in range(1, (pages or ESTABLISHED_PAGES) + 1):
        try:
            resp = requests.get(GECKO_POOLS_URL, params={
                "sort": "h24_volume_usd_desc", "page": page, "include": "base_token,quote_token"}, timeout=15)
            resp.raise_for_status()
            payload = resp.json()
        except Exception:
            continue
        for item in payload.get("data", []):
            a = item.get("attributes") or {}
            addr = _gecko_resolve(item, payload.get("included", []))
            try:
                liq = float(a.get("reserve_in_usd") or 0)
                vol = float((a.get("volume_usd") or {}).get("h24") or 0)
            except (TypeError, ValueError):
                continue
            age = _age_days(a)
            if not addr or not ADDR_RE.fullmatch(addr) or addr.lower() in SKIP:
                continue
            if liq < MIN_LIQ or vol < MIN_VOL or age is None or age < MIN_AGE_DAYS:
                continue
            rows.append({"token_address": addr, "why": "established", "liquidity_usd": liq,
                         "volume24h_usd": vol, "age_days": age})
    rows.sort(key=lambda x: x["volume24h_usd"], reverse=True)
    return rows[:limit]


def trending_candidates(limit=20):
    out = []
    try:
        resp = requests.get(GECKO_TRENDING_URL, params={"include": "base_token,quote_token"}, timeout=15)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        return out
    for item in payload.get("data", []):
        a = item.get("attributes") or {}
        addr = _gecko_resolve(item, payload.get("included", []))
        try:
            liq = float(a.get("reserve_in_usd") or 0)
        except (TypeError, ValueError):
            continue
        if addr and ADDR_RE.fullmatch(addr) and addr.lower() not in SKIP and liq >= MIN_LIQ:
            out.append({"token_address": addr, "why": "trending", "liquidity_usd": liq})
    return out[:limit]


def discover(max_candidates=60):
    """All three nets, de-duplicated by address, capped."""
    seen, merged = set(), []
    for batch in (search_candidates(), established_candidates(), trending_candidates()):
        for c in batch:
            k = c["token_address"].lower()
            if k not in seen:
                seen.add(k)
                merged.append(c)
    return merged[:max_candidates]
