"""
Tests des modules 10 (anti-spam) et 11 (anti-scam).
Pas de Discord, pas de Redis — la logique de détection est testée
de façon complètement stateless.
"""
from __future__ import annotations

import pytest
from bot.modules.antiscam import analyze, ScamResult


# ── Tests antiscam ────────────────────────────────────────────────────

def test_clean_message_not_flagged():
    result = analyze("Bonjour tout le monde, comment allez-vous ?")
    assert not result.is_scam
    assert result.score == 0.0


def test_nitro_gratuit_flagged():
    result = analyze("Clique ici pour avoir du nitro gratuit !")
    assert result.is_scam
    assert result.score >= 0.50
    assert any("phishing" in r for r in result.reasons)


def test_discord_invite_flagged():
    result = analyze("Rejoins notre serveur : https://discord.gg/abc123")
    assert result.is_scam
    assert len(result.invite_links) == 1
    assert result.score >= 0.50


def test_discord_invite_allowed_when_permitted():
    result = analyze("Rejoins notre serveur : https://discord.gg/abc123", allow_invites=True)
    assert not result.invite_links or not result.is_scam or result.score < 0.55


def test_suspicious_url_flagged():
    result = analyze("Clique vite : https://bit.ly/win-free-gift")
    assert result.is_scam
    assert result.suspicious_urls


def test_combined_url_and_phishing_gives_high_score():
    result = analyze("You won! Click here now: https://bit.ly/free-nitro-discord")
    assert result.is_scam
    assert result.score >= 0.80


def test_steam_scam_flagged():
    result = analyze("Steam gift card free ! You won a gift card, claim now!")
    assert result.is_scam


def test_crypto_giveaway_flagged():
    result = analyze("Crypto giveaway! Free airdrop — limited time offer!")
    assert result.is_scam
    assert result.score >= 0.50


def test_verify_account_flagged():
    result = analyze("Please verify your account immediately to avoid suspension.")
    assert result.is_scam


def test_phishing_discord_nitro_domain():
    result = analyze("Claim your reward: https://discord-nitro.xyz/free")
    assert result.is_scam
    assert result.score >= 0.65


def test_empty_message_not_flagged():
    result = analyze("")
    assert not result.is_scam
    assert result.score == 0.0


def test_multiple_reasons_accumulated():
    """URL raccourcie + phishing → deux raisons listées."""
    result = analyze("Tu as gagné ! Clique ici vite : https://tinyurl.com/fake")
    assert result.is_scam
    assert len(result.reasons) >= 2


def test_spaced_keywords_flagged():
    """Évasion par espaces intercalés (n i t r o g r a t u i t)."""
    result = analyze("Clique ici pour avoir du n i t r o   g r a t u i t !")
    assert result.is_scam
    assert any("phishing" in r for r in result.reasons)


def test_homoglyphs_flagged():
    """Évasion par homoglyphes cyrilliques (і, о, а)."""
    result = analyze("Clique ici pour du nіtrо grаtuіt !")
    assert result.is_scam
    assert any("phishing" in r for r in result.reasons)


def test_embed_scam_flagged():
    """Détection de scam à l'intérieur d'un embed Discord."""
    from types import SimpleNamespace
    embed = SimpleNamespace(
        title="Free Nitro Giveaway",
        description="Claim your reward at https://discord-nitro.xyz/free",
        url=None,
        author=None,
        footer=None,
        fields=[],
    )
    result = analyze("", embeds=[embed])
    assert result.is_scam
    assert result.score >= 0.65


def test_dangerous_attachment_flagged():
    """Détection de fichier attaché exécutable ou dangereux (.exe)."""
    from types import SimpleNamespace
    att = SimpleNamespace(
        filename="free_nitro_generator.exe",
        description=None,
    )
    result = analyze("Regarde ce fichier", attachments=[att])
    assert result.is_scam
    assert any("dangereux" in r for r in result.reasons)
    assert result.score >= 0.90


def test_double_extension_attachment_flagged():
    """Détection de double extension trompeuse (photo.png.scr)."""
    from types import SimpleNamespace
    att = SimpleNamespace(
        filename="gift_card.png.scr",
        description=None,
    )
    result = analyze("", attachments=[att])
    assert result.is_scam
    assert any("dangereux" in r for r in result.reasons)


def test_money_lure_paypal_flagged():
    """Appât financier (100 balles paypal)."""
    result = analyze("Qui veut gagner 100 balles paypal now?")
    assert result.is_scam
    assert result.score >= 0.80
    assert any("appât financier" in r for r in result.reasons)


def test_bio_redirect_flagged():
    """Contournement par lien en bio."""
    result = analyze("Cliquer sur mon lien en bio alors")
    assert result.is_scam
    assert result.score >= 0.80
    assert any("lien en bio" in r for r in result.reasons)


def test_dm_lure_flagged():
    """Incitation à passer en privé pour des gains."""
    result = analyze("Viens pv pour gagner 50€ paypal")
    assert result.is_scam
    assert result.score >= 0.75
    assert any("message privé" in r for r in result.reasons)


def test_social_engineering_flagged():
    """Fausses sollicitations de tournoi / test de jeu."""
    result = analyze("Vote pour notre team pour le tournoi s'il vous plaît")
    assert result.is_scam
    assert result.score >= 0.75
    assert any("ingénierie sociale" in r for r in result.reasons)


def test_combined_money_and_bio_cumulative_score():
    """Combinaison appât financier + lien en bio → score critique élevé."""
    result = analyze("Qui veut gagner 100 balles paypal now? Cliquer sur mon lien en bio alors")
    assert result.is_scam
    assert result.score >= 0.90
    assert len(result.reasons) >= 2


def test_raid_threat_flagged():
    """Menace directe de raid ou de nuke du serveur."""
    result1 = analyze("Je vais raid le serv les gars")
    assert result1.is_scam
    assert result1.score == 1.0
    assert any("menace d'attaque" in r for r in result1.reasons)

    result2 = analyze("Je préviens directe je vais faire sauter le serveur")
    assert result2.is_scam
    assert result2.score == 1.0


def test_bio_invite_flagged():
    """Publicité / invitation déguisée en bio."""
    result = analyze("Rejoignez mon serv en bio les bg")
    assert result.is_scam
    assert result.score >= 0.85
    assert any("bio" in r for r in result.reasons)



