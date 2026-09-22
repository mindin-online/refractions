"""
refraction_honeypot_check.py

Honeypot and broader contract-security check via GoPlus Security's free
public API -- no key required, covers Base directly (chain_id 8453).
Endpoint: GET https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}

This logic is ported from a working, incident-tested implementation
(a separate Base sniper bot's security.js), not written from scratch --
the specific checks and thresholds below trace back to real losses that
motivated each one. Preserved here so the reasoning travels with the
code:

- is_in_dex == '0' check: a GoPlus record can EXIST but be a stub -- no
  real analysis behind it -- for a pool too new for GoPlus to have
  indexed as tradable. Seen firsthand: is_honeypot came back "0" and
  sell_tax/buy_tax came back as empty strings, which a naive check reads
  as "0% tax, all clear" -- false confidence, not a real clean bill of
  health.
- missing is_honeypot field: seen firsthand on two real Base launchpad
  tokens where the field was completely absent from the response. A
  naive check (`data.get('is_honeypot') == '1'`) reads a missing field
  as "not a honeypot" since undefined != '1' -- false confidence on
  exactly the field this check exists for. This is the single most
  important fix versus a naive implementation: missing must fail
  CLOSED, not pass by default.
- is_open_source == '0': HARD gate, unconditional, after a real incident
  where an unverified contract had a hidden function letting its
  deployer directly seize/burn any holder's balance -- invisible in
  advance because the bytecode was never published. If the code can't
  be read, nothing (not GoPlus, not this check) can rule out anything
  it might do.
- owner_change_balance == '1': the exact mechanism that drained a real
  position via a Multicall from a third-party address rewriting a
  balance directly, with zero transaction from the holder's own wallet.
- holder concentration via GoPlus's own holder list, WITH exemptions for
  locked/LP/Burn-tagged holders and (only when the token itself is
  verified) contract holders -- a contract holding a large stake isn't
  automatically fine just because it's a contract; an unverified
  "vault" holding nearly everything is exactly the risk this exists to
  catch, not exempt from it.

This is deliberately kept as a SEPARATE, independent module from
refraction_check.py's own on-chain holder-concentration check rather
than merged into it -- same "independent checks, not folded together"
reasoning as running this alongside honeypot.is in
refraction_honeypot_is_check.py: a blind spot or outage in one source
shouldn't silently take out the other.
"""
import os
import requests

GOPLUS_URL_TEMPLATE = "https://api.gopluslabs.io/api/v1/token_security/{}"
BASE_CHAIN_ID = "8453"

MAX_SELL_TAX = float(os.environ.get("REFRACTION_MAX_SELL_TAX", "0.30"))
MAX_BUY_TAX = float(os.environ.get("REFRACTION_MAX_BUY_TAX", "0.30"))
MAX_HOLDER_PERCENT = float(os.environ.get("REFRACTION_MAX_GOPLUS_HOLDER_PCT", "0.20"))
MAX_CREATOR_PERCENT = float(os.environ.get("REFRACTION_MAX_CREATOR_PCT", "0.15"))


def check_honeypot(token_address: str) -> dict:
    """
    Returns:
      ok=True:  {"ok": True, "is_safe": bool, "reason": str, "buy_tax_pct": float, "sell_tax_pct": float}
      ok=False: {"ok": False, "reason": str}   (couldn't verify -- treat as unsafe, same as the source)

    Note the two-level shape: "ok" means "did we get a usable answer at
    all" (matches every other check module in this codebase); "is_safe"
    is the actual verdict once we did.
    """
    def unsafe(reason):
        return {"ok": True, "is_safe": False, "reason": reason, "buy_tax_pct": None, "sell_tax_pct": None}

    try:
        resp = requests.get(
            GOPLUS_URL_TEMPLATE.format(BASE_CHAIN_ID),
            params={"contract_addresses": token_address.lower()},
            timeout=15,
        )
        if not resp.ok:
            return {"ok": False, "reason": f"GoPlus API returned {resp.status_code}"}
        data = resp.json()
    except Exception as e:
        return {"ok": False, "reason": f"GoPlus request failed: {e}"}

    info = (data.get("result") or {}).get(token_address.lower())
    if not info:
        return unsafe("Token not yet indexed by GoPlus -- too new to verify, blocking buy.")

    # A record can exist but be a stub for a pool too new to be indexed as
    # tradable -- is_in_dex is the tell. Without this, a record existing
    # at all was enough to pass, even when every real safety field in it
    # was empty/placeholder data.
    if info.get("is_in_dex") == "0":
        return unsafe("GoPlus hasn't indexed this token in a DEX yet -- too new to verify tax/honeypot behavior, blocking buy.")

    # Missing is_honeypot must fail CLOSED -- the core fix versus a naive
    # implementation. A missing field is not the same as a "0" verdict.
    if "is_honeypot" not in info or info.get("is_honeypot") is None:
        return unsafe("GoPlus did not return a honeypot verdict for this token -- can't verify, blocking buy.")
    if info.get("is_honeypot") == "1":
        return unsafe("GoPlus flags this token as a honeypot (cannot be resold).")
    if info.get("cannot_sell_all") == "1":
        return unsafe("GoPlus flags this token as unable to fully sell.")

    sell_tax = float(info.get("sell_tax") or 0)
    buy_tax = float(info.get("buy_tax") or 0)
    if sell_tax > MAX_SELL_TAX:
        return unsafe(f"Sell tax too high ({sell_tax * 100:.0f}%).")
    if buy_tax > MAX_BUY_TAX:
        return unsafe(f"Buy tax too high ({buy_tax * 100:.0f}%).")

    if info.get("is_blacklisted") == "1" or (
        info.get("is_whitelisted") == "0" and info.get("is_open_source") == "0" and info.get("hidden_owner") == "1"
    ):
        return unsafe("GoPlus flags ownership/blacklist risk on this token.")

    # HARD GATE, no exceptions: an unverified contract can hide literally
    # anything -- nothing can rule out a hidden owner-only seize/burn
    # function if the bytecode was never published.
    if info.get("is_open_source") == "0":
        return unsafe("Contract source is not verified/published -- cannot rule out hidden owner-only transfer/burn functions, refusing to buy.")
    if info.get("is_proxy") == "1":
        return unsafe("Proxy contract -- the token's logic can be swapped out by its deployer at any time after launch, too risky to buy.")

    if info.get("is_mintable") == "1":
        return unsafe("Token owner can mint new supply at will (is_mintable) -- dilution risk.")
    if info.get("can_take_back_ownership") == "1":
        return unsafe("Ownership can be reclaimed even if it looks renounced (can_take_back_ownership).")
    if info.get("transfer_pausable") == "1":
        return unsafe("Owner can pause all transfers at will (transfer_pausable).")
    if info.get("slippage_modifiable") == "1" and info.get("personal_slippage_modifiable") == "1":
        return unsafe("Owner can set a custom tax/slippage rate per-wallet (personal_slippage_modifiable) -- can single out and drain specific holders.")

    # The exact mechanism confirmed to have drained a real position via a
    # third-party Multicall directly rewriting a balance, with zero
    # transaction from the holder's own wallet.
    if info.get("owner_change_balance") == "1":
        return unsafe("Owner can directly rewrite ANY holder's balance (owner_change_balance) -- known real drain mechanism, hard blocked.")
    if info.get("selfdestruct") == "1":
        return unsafe("Contract can self-destruct (selfdestruct) -- owner can kill it and everything in it at will.")

    if int(info.get("honeypot_with_same_creator") or 0) > 0:
        return unsafe(f"This token's creator has deployed {info.get('honeypot_with_same_creator')} known honeypot(s) before -- repeat offender, blocked.")

    transfer_tax = float(info.get("transfer_tax") or 0)
    if transfer_tax > MAX_SELL_TAX:
        return unsafe(f"Transfer tax too high ({transfer_tax * 100:.0f}%) -- applies to all transfers, not just trades.")

    # Holder concentration via GoPlus's own list. Exempt locked/LP/Burn
    # holders always; exempt contract holders only when the TOKEN ITSELF
    # is verified -- an unverified "vault" holding nearly everything is
    # exactly the risk this exists to catch, not a pass.
    token_verified = info.get("is_open_source") == "1"
    for h in (info.get("holders") or []):
        if h.get("is_locked") == "1" or h.get("tag") in ("LP", "Burn"):
            continue
        if h.get("is_contract") == "1" and token_verified:
            continue
        pct = float(h.get("percent") or 0)
        if pct > MAX_HOLDER_PERCENT:
            who = "An unverified contract" if h.get("is_contract") == "1" else "A single unlocked wallet"
            return unsafe(f"{who} holds {pct * 100:.0f}% of supply (>{MAX_HOLDER_PERCENT * 100:.0f}% limit) -- whale-dump / manipulation risk.")

    creator_pct = float(info.get("creator_percent") or 0)
    if creator_pct > MAX_CREATOR_PERCENT:
        return unsafe(f"Creator wallet still holds {creator_pct * 100:.0f}% of supply (>{MAX_CREATOR_PERCENT * 100:.0f}% limit).")

    return {
        "ok": True,
        "is_safe": True,
        "reason": "Passed honeypot/tax/ownership/concentration checks.",
        "buy_tax_pct": buy_tax * 100,
        "sell_tax_pct": sell_tax * 100,
    }
