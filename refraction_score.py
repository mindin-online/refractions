"""
refraction_score.py

One 0-100 quality score per candidate, plus an explicit buy decision.

HOW IT'S SPLIT (and why)
  Cheap categories -- computed on every candidate that shows any reward
  mechanism, using only free/cheap data:
      Mechanism   25   a real pattern, paid in a mainstream external asset
      Autonomy    25   can anyone steer or stop the payout?
      Payouts     15   proven from logs, not from marketing
      Market      15   liquidity, volume, market cap, two-sided trading
  Expensive category -- only run when a candidate looks promising enough
  (cheap points >= REFRACTION_STAGE3_MIN_PRE_PCT of 80) or already passed
  the structural gates:
      Code/fraud  20   GoPlus, honeypot.is, transfer-tax simulation, LP
                       lock, ERC-4626 inflation exposure
  A score computed without the expensive category is marked PARTIAL and is
  scaled to 100 so it reads on the same scale; treat it as provisional.

FRAUD IS A GATE, NOT JUST POINTS. Any confirmed hard fail (GoPlus unsafe,
honeypot.is unsafe, a transfer tax, locked-LP shortfall) blocks the buy
no matter how high the score is. Inconclusive checks also block a buy
(fail closed) but are reported separately from confirmed failures.

BUY RULE (your decision): a candidate is buy-eligible only if ALL hold --
  * a qualifying pattern (Synthetix / ERC-4626 / dividend tracker)
  * the reward asset is external and mainstream (USDC / WETH / cbBTC)
  * payouts are proven (strong; events-only only if explicitly allowed)
  * autonomy is "autonomous" (constrained only if explicitly allowed)
  * the holder-concentration gate passes
  * liquidity is above the buy floor
  * no hard fails, no inconclusive required check
  * the final score >= REFRACTION_BUY_MIN_SCORE (default 75)
This is deliberately strict. Expect very few buys.
"""
import os

BUY_MIN_SCORE = int(os.environ.get("REFRACTION_BUY_MIN_SCORE", "75"))
STAGE3_MIN_PRE_PCT = float(os.environ.get("REFRACTION_STAGE3_MIN_PRE_PCT", "0.60"))
ALLOW_CONSTRAINED = os.environ.get("REFRACTION_ALLOW_CONSTRAINED", "0") not in ("0", "false", "False", "")
ALLOW_EVENT_ONLY = os.environ.get("REFRACTION_ALLOW_EVENT_ONLY_PROOF", "0") not in ("0", "false", "False", "")
MIN_LIQUIDITY_USD = float(os.environ.get("REFRACTION_MIN_LIQUIDITY_USD", "5000"))
REQUIRE_ZERO_TAX = os.environ.get("REFRACTION_REQUIRE_ZERO_TAX", "1") not in ("0", "false", "False", "")
# Dividend-tracker tokens usually FUND their payouts with a 4-10% buy/sell tax,
# so "0% tax required" rules out nearly all of them by design. Default stays
# strict (your earlier standard). To allow taxed payers set
# REFRACTION_REQUIRE_ZERO_TAX=0; the measured tax must then stay under
# REFRACTION_MAX_TRADE_TAX_PCT (default 10) or it is still a hard fail.
MAX_TRADE_TAX_PCT = float(os.environ.get("REFRACTION_MAX_TRADE_TAX_PCT", "10"))
BUY_USD = float(os.environ.get("REFRACTION_BUY_USD", "10"))
REQUIRE_GOPLUS = os.environ.get("REFRACTION_REQUIRE_HONEYPOT_SAFE", "1") not in ("0", "false", "False", "")
REQUIRE_HPIS = os.environ.get("REFRACTION_REQUIRE_HONEYPOT_IS_SAFE", "1") not in ("0", "false", "False", "")

CHEAP_MAX = 80
QUALIFYING = ("synthetix", "erc4626", "dividend")


def _tier(value, tiers):
    """tiers: [(threshold, points), ...] descending."""
    for threshold, pts in tiers:
        if value is not None and value >= threshold:
            return pts
    return 0


def has_reward_signal(result: dict) -> bool:
    """Is there ANY reward-mechanism evidence worth logging/scoring?"""
    d = result["detail"]
    return bool(
        d["interface"].get("is_match")
        or d.get("dividend", {}).get("detected")
        or d.get("classic_reflection", {}).get("detected")
    )


def _mechanism(result):
    d = result["detail"]
    iface, reward = d["interface"], d["reward"]
    pts, notes = 0, []
    pattern = iface.get("pattern") if iface.get("is_match") else None
    if pattern in QUALIFYING:
        pts += 10
    elif d.get("classic_reflection", {}).get("detected"):
        pts += 2
        notes.append("classic reflection pays in the same token")
    if reward.get("ok") and reward.get("reward_token"):
        if reward.get("is_mainstream"):
            pts += 10
        elif "itself" in (reward.get("label") or ""):
            pts += 1
        else:
            pts += 4
    if pattern in ("synthetix", "erc4626"):
        pts += 5
    elif pattern == "dividend":
        pts += min(5, len(d.get("dividend", {}).get("matched_selectors", [])))
    return min(pts, 25), 25, notes


def _autonomy(result):
    a = result["detail"].get("autonomy")
    iface = result["detail"]["interface"]
    if not a or not iface.get("is_match"):
        return 0, 25
    return {"autonomous": 25, "constrained": 12, "unknown": 5, "managed": 0}.get(a["level"], 0), 25


def _payouts(result):
    p = result["detail"].get("payouts")
    if not p or not p.get("ran"):
        return 0, 15
    pts = 0
    if p["proof"] == "strong":
        e = p["erc20"]
        pts = 8 + _tier(e["recipients"], [(50, 4), (25, 3), (10, 2)]) + _tier(e["active_days"], [(3, 3), (2, 2)])
    elif p["proof"] in ("events_only", "drift_only"):
        pts = 5 + (2 if p["events"]["auto_claims"] > 0 else 0)
    if p["trigger"]["verdict"] == "manual_push":
        pts = max(0, pts - 3)
    return min(pts, 15), 15


def _market(result, pool):
    pts = 0
    liq, vol = pool.get("liquidity_usd"), pool.get("volume24h_usd")
    cap = pool.get("market_cap_usd") or pool.get("fdv_usd")
    pts += _tier(liq, [(50000, 5), (20000, 4), (5000, 3), (1000, 1)])
    pts += _tier(vol, [(50000, 4), (10000, 3), (1000, 1)])
    pts += _tier(cap, [(1000000, 2), (100000, 1)])
    if result["steps"].get("holder_concentration_pass"):
        pts += 2
    if (pool.get("buys24h") or 0) > 0 and (pool.get("sells24h") or 0) > 0:
        pts += 2
    return min(pts, 15), 15


def _stage3(result, stage3):
    """-> (points, max, hard_fails, inconclusive)"""
    pts, hard, incon = 0, [], []
    gp, hp, tax = stage3.get("goplus"), stage3.get("honeypot_is"), stage3.get("tax")
    if gp is not None:
        if not gp.get("ok"):
            incon.append(f"GoPlus inconclusive: {gp.get('reason')}")
        elif not gp.get("is_safe"):
            hard.append(f"GoPlus: {gp.get('reason')}")
        else:
            pts += 6
            lp = gp.get("lp_locked_pct")
            if lp is not None and lp >= 80:
                pts += 3
    if hp is not None:
        if not hp.get("ok"):
            incon.append(f"honeypot.is inconclusive: {hp.get('reason')}")
        elif not hp.get("is_safe"):
            hard.append(f"honeypot.is: {hp.get('reason')}")
        else:
            pts += 5
    if tax is not None:
        if not tax.get("ok"):
            incon.append(f"tax check inconclusive: {tax.get('reason')}")
        elif not tax.get("is_zero_tax"):
            pct = tax.get("tax_pct", 0)
            if REQUIRE_ZERO_TAX:
                hard.append(f"transfer tax ~{pct:.2f}% (zero tax is required)")
            elif pct > MAX_TRADE_TAX_PCT:
                hard.append(f"transfer tax ~{pct:.2f}% (over the {MAX_TRADE_TAX_PCT:.0f}% cap)")
            else:
                pts += 2  # taxed, but within the allowed cap
        else:
            pts += 4
    vr = result["detail"].get("vault_risk", {})
    if not (vr.get("applicable") and vr.get("ok") and vr.get("inflation_risk")):
        pts += 2
    return min(pts, 20), 20, hard, incon


def grade_for(score: int) -> str:
    return "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D"


def score_candidate(result: dict, pool: dict, stage3: dict = None) -> dict:
    d = result["detail"]
    comp = {}
    notes = []
    m, mm, mn = _mechanism(result)
    notes += mn
    comp["mechanism"] = (m, mm)
    comp["autonomy"] = _autonomy(result)
    comp["payouts"] = _payouts(result)
    comp["market"] = _market(result, pool)
    cheap = sum(p for p, _ in comp.values())
    pre_pct = cheap / CHEAP_MAX

    hard, incon, partial = [], [], True
    total = None
    if stage3 is not None and any(stage3.get(k) is not None for k in ("goplus", "honeypot_is", "tax")):
        s3, s3max, hard, incon = _stage3(result, stage3)
        comp["code_fraud"] = (s3, s3max)
        total = cheap + s3
        partial = False
    score = total if total is not None else round(cheap / CHEAP_MAX * 100)

    # ---- buy decision -------------------------------------------------
    blockers = []
    iface = d["interface"]
    pattern = iface.get("pattern") if iface.get("is_match") else None
    reward = d["reward"]
    a = d.get("autonomy") or {}
    p = d.get("payouts") or {}
    if pattern not in QUALIFYING:
        blockers.append("no qualifying pattern (Synthetix / ERC-4626 / dividend tracker)")
    if not (reward.get("ok") and reward.get("is_mainstream")):
        blockers.append("reward asset is not an external mainstream asset (USDC/WETH/cbBTC)")
    proof = p.get("proof")
    if not (proof == "strong" or (proof in ("events_only", "drift_only") and ALLOW_EVENT_ONLY)):
        blockers.append(f"payouts not proven ({proof or 'not checked'})")
    level = a.get("level")
    if not (level == "autonomous" or (level == "constrained" and ALLOW_CONSTRAINED)):
        blockers.append(f"payout is not autonomous ({level or 'not checked'})")
    if not result["steps"].get("holder_concentration_pass"):
        blockers.append("holder concentration gate failed")
    mb = d.get("min_balance") or {}
    if mb.get("ok") and not mb.get("qualifies"):
        blockers.append(
            f"a ${BUY_USD:.0f} buy gets ~{mb['expected_tokens']:,.0f} tokens but this tracker only pays "
            f"holders of >= {mb['min_tokens']:,.0f} (~${mb['min_usd']:,.0f}) -- you would earn nothing")
    liq = pool.get("liquidity_usd") or 0
    if liq < MIN_LIQUIDITY_USD:
        blockers.append(f"liquidity ${liq:,.0f} below the ${MIN_LIQUIDITY_USD:,.0f} floor")
    if stage3 is None:
        blockers.append("pre-buy fraud checks not run yet")
    else:
        if REQUIRE_GOPLUS and stage3.get("goplus") is None:
            blockers.append("GoPlus not run")
        if REQUIRE_HPIS and stage3.get("honeypot_is") is None:
            blockers.append("honeypot.is not run")
        if REQUIRE_ZERO_TAX and stage3.get("tax") is None:
            blockers.append("tax check not run")
    blockers += [f"HARD FAIL -- {h}" for h in hard]
    blockers += incon
    if not partial and score < BUY_MIN_SCORE:
        blockers.append(f"score {score} below the buy minimum {BUY_MIN_SCORE}")

    return {
        "score": score, "grade": grade_for(score), "partial": partial,
        "cheap_points": cheap, "cheap_max": CHEAP_MAX, "pre_pct": pre_pct,
        "components": comp, "hard_fails": hard, "inconclusive": incon,
        "buy_eligible": not blockers, "buy_blockers": blockers, "notes": notes,
    }


def should_run_stage3(result: dict, sc: dict) -> bool:
    """Spend the expensive API calls only on promising candidates."""
    return bool(result.get("passes_all")) or sc["pre_pct"] >= STAGE3_MIN_PRE_PCT


def short_tag(sc: dict) -> str:
    return f"[{'~' if sc['partial'] else ''}{sc['score']} {sc['grade']}]"


def one_line(result: dict, sc: dict) -> str:
    d = result["detail"]
    a, p = d.get("autonomy") or {}, d.get("payouts") or {}
    bits = [f"score {short_tag(sc)}"]
    if a.get("level"):
        bits.append(f"autonomy {a['level']}")
    if p.get("ran"):
        e = p["erc20"]
        extra = f" ({e['label'] or 'asset'}, {e['recipients']} recipients)" if p["proof"] == "strong" else ""
        bits.append(f"payouts {p['proof']}{extra}")
    return " · ".join(bits)
