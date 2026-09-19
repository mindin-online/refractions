"""
Snippet to merge into mojohawk_discord_bot.py.

Adds a /check slash command for manually testing a candidate contract
through the full refraction pipeline (interface match, holder
concentration, reward token, Aerodrome gauge) -- useful for checking an
address you found yourself, without waiting for the scanner feed.

This command is READ-ONLY: it reports the result, it does not buy. If you
want /check to also trigger a buy on a pass, add the same daily-cap /
liquidity-floor / execute_buy call that refraction_scanner.py uses (import
those pieces from there rather than duplicating the logic).

Assumes `bot` is your existing discord.py Bot/Client instance with a
command tree already set up (matches your /kbuy, /ksell pattern).
"""
import discord
from discord import app_commands

from refraction_check import check_refraction


@bot.tree.command(name="check", description="Run a Base contract through the full refraction pipeline")
@app_commands.describe(address="Contract address to check")
async def check(interaction: discord.Interaction, address: str):
    await interaction.response.defer()
    try:
        result = check_refraction(address)
    except Exception as e:
        await interaction.followup.send(f"⚠️ Check failed for `{address}`: {e}")
        return

    overall = "✅ PASSES all required gates" if result["passes_all"] else "❌ does not pass"
    lines = [f"`{result['address']}` — {overall}"]
    if result.get("logic_address"):
        lines.append(f"(proxy → implementation `{result['logic_address']}`)")

    active = set(result["gates_active"])
    for name, passed in result["steps"].items():
        marker = "✓" if passed else "✗"
        tag = " (required)" if name in active else " (bonus)"
        lines.append(f"{marker} {name}{tag}")

    interface = result["detail"]["interface"]
    if interface["pattern"]:
        lines.append(f"  interface pattern: {interface['pattern']}")

    holders = result["detail"]["holders"]
    if holders["ok"]:
        lines.append(
            f"  top holder: `{holders['top_holder_address']}` "
            f"({'contract' if holders['top_holder_is_contract'] else 'EOA'}, "
            f"{holders['top_holder_pct']:.1f}% of supply)"
        )
    else:
        lines.append(f"  holder data unavailable: {holders['reason']}")

    reward = result["detail"]["reward"]
    if reward["ok"]:
        lines.append(f"  reward token: `{reward['reward_token']}`" + (f" ({reward['label']})" if reward["label"] else ""))

    await interaction.followup.send("\n".join(lines))
