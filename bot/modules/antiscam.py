"""
Module 11 — Anti-scam / anti-liens.

Détecte dans les messages :
  1. Liens Discord d'invitation non autorisés (discord.gg/*)
  2. Patterns de phishing classiques (nitro gratuit, clique ici, steam free, etc.)
  3. URLs suspectes (raccourcisseurs, domaines connus pour le phishing)

Actions configurables :
  - Supprimer le message
  - Avertir l'utilisateur en public ou en DM
  - Émettre un événement "risk_critical" si le score est assez élevé

Les patterns sont intentionnellement simples (regex) pour éviter les faux
positifs — le module agit vite sur les cas évidents, laisse le scoring
de légitimité (module 3) gérer les cas ambigus.
"""
from __future__ import annotations

import datetime
import logging
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field

import discord

logger = logging.getLogger("sentinel.antiscam")


# ── Patterns de détection ─────────────────────────────────────────────

# Invitations Discord (discord.gg / discord.com/invite / discordapp.com/invite)
DISCORD_INVITE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[\w-]+",
    re.IGNORECASE,
)

# URLs raccourcies et domaines phishing connus
SUSPICIOUS_URL_RE = re.compile(
    r"(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|buff\.ly"
    r"|rebrand\.ly|cutt\.ly|shorturl\.at|discord-nitro\.|discordnitro\."
    r"|steamcommun1ty\.|steampowered-free\.)",
    re.IGNORECASE,
)

# 1. Menaces d'attaque, raid, nuke ou destruction du serveur
RAID_THREAT_RE = re.compile(
    r"\b(?:"
    r"(?:je\s*vais|on\s*va|j'vais|jvais|go|on\s*go)\s*.{0,20}(?:raid|nuke|faire\s*sauter|crash|ddos|détruire|detruire|hack|hacker|dox|doxx|détruit)\s*.{0,20}(?:le\s*serv|ce\s*serv|le\s*serveur|ce\s*serveur|discord)\b"
    r"|(?:je\s*préviens|je\s*previens|attention).{0,25}(?:faire\s*sauter|raid|nuke|crash|détruire|detruire)\s*.{0,20}(?:le\s*serv|ce\s*serv|le\s*serveur|ce\s*serveur)\b"
    r"|(?:raid|nuke|faire\s*sauter|crash)\s*(?:ce|le)\s*(?:serv|serveur)\b"
    r"|(?:serveur|serv)\s*.{0,15}(?:va\s*sauter|va\s*mourir|va\s*crash)\b"
    r")",
    re.IGNORECASE,
)

# 2. Phishing classique (Nitro, Steam, alertes compte)
SCAM_KEYWORDS_RE = re.compile(
    r"\b(?:"
    r"nitro.{0,20}(?:gratuit|free|offert|offer|giveaway|gratis)"
    r"|(?:gratuit|free|offert|offer|giveaway|gratis).{0,20}nitro"
    r"|steam.{0,20}(?:gift|free|gratuit|giveaway)"
    r"|(?:free|gratuit|giveaway).{0,20}steam"
    r"|clique\s*(?:ici|here|vite)"
    r"|click\s*here\s*(?:now|fast|quick)?"
    r"|gift\s*card\s*(?:free|gratuit|win|won)"
    r"|tu\s*as\s*(?:gagné|gagne)\s"
    r"|you\s*(?:won|win|have\s*won)"
    r"|compte\s*(?:piraté|hacké|compromis)"
    r"|verify\s*your\s*account"
    r"|limited\s*time\s*offer"
    r"|crypto\s*(?:giveaway|airdrop|free)"
    r"|@everyone.{0,30}(?:free|gratuit|nitro|giveaway)"
    r")\b",
    re.IGNORECASE,
)

# 3. Appâts financiers / faux gains (Paypal, CashApp, Robux, V-Bucks, 100 balles...)
MONEY_LURE_RE = re.compile(
    r"\b(?:"
    r"(?:qui\s*veut)\s*.{0,25}(?:gagner|toucher|avoir|prendre|win|earn)\s*.{0,25}(?:paypal|argent|cash|balles?|euros?|\$|€|bucks?|crypto|nitro)\b"
    r"|(?:gagner?|gagnez?|win|earn|toucher?)\s*.{0,25}(?:\d+\s*(?:€|\$|euros?|balles?|dollars?)|argent|cash|paypal|crypto)\b"
    r"|(?:\d+\s*(?:€|\$|euros?|balles?|dollars?))\s*.{0,25}(?:paypal|cashapp|paysafe|crypto|btc|eth|gratuit|free|offert)\b"
    r"|(?:paypal|cashapp|crypto)\s*.{0,25}(?:gratuit|free|offert|giveaway|money|argent)\b"
    r"|(?:argent|cash)\s*(?:facile|rapide|gratuit|free|illimité)\b"
    r"|(?:robux|v-?bucks|riot\s*points)\s*(?:free|gratuit|generator|illimité|unlimited|giveaway)\b"
    r"|(?:free|gratuit)\s*(?:robux|v-?bucks|riot\s*points)\b"
    r")",
    re.IGNORECASE,
)

# 4. Contournement par le profil / lien en bio ("cliquer sur mon lien en bio", "check ma bio")
BIO_REDIRECT_RE = re.compile(
    r"\b(?:"
    r"(?:lien|link|site|url)\s*.{0,10}(?:en|dans|in|sur)?\s*(?:ma|mon|my|the)?\s*bio\b"
    r"|(?:clique|cliquer|cliquez|click|go|check|regarde|voir|matte)\s*.{0,25}(?:lien|link)?\s*(?:en|dans|in|sur)?\s*(?:ma|mon|my|the)?\s*bio\b"
    r"|(?:check|voir|regarde)\s*(?:ma|my)\s*bio\b"
    r"|(?:lien|link)\s*.{0,15}(?:en|sur|dans)?\s*(?:mon|le|my)?\s*(?:profil|status|statut)\b"
    r")",
    re.IGNORECASE,
)

# 5. Publicité / invitation de serveur en bio ("rejoignez mon serv en bio")
BIO_INVITE_RE = re.compile(
    r"\b(?:"
    r"(?:rejoins|rejoignez|go)\s*.{0,20}(?:mon|notre|le)?\s*(?:serv|serveur|server|discord)\s*.{0,20}(?:en|dans|sur)?\s*(?:ma|mon|la)?\s*bio\b"
    r"|(?:mon|le)\s*(?:serv|serveur|discord)\s*.{0,15}(?:est|dispo)?\s*(?:en|dans|sur)\s*(?:ma|mon)?\s*bio\b"
    r")",
    re.IGNORECASE,
)

# 6. Sollicitation en privé suspecte (viens pv pour gagner/nitro...)
DM_LURE_RE = re.compile(
    r"\b(?:"
    r"(?:viens|venez|go|mp|dm|écris|ecris)\s*(?:en|in)?\s*(?:pv|mp|dm|privé|prive|private)\s*.{0,25}(?:pour|to|avoir|gagner|toucher|free|gratuit|argent|paypal|nitro|robux)\b"
    r"|(?:mp|dm)\s*(?:moi|me)\s*.{0,25}(?:pour|to|avoir|gagner|toucher|free|gratuit|argent|paypal|nitro|robux)\b"
    r")",
    re.IGNORECASE,
)

# 7. Ingénierie sociale (vote pour ma team, teste mon jeu)
SOCIAL_ENG_RE = re.compile(
    r"\b(?:"
    r"(?:vote|voter|votez)\s*(?:pour|for)\s*(?:mon|ma|notre|our|my)\s*(?:team|équipe|equipe|tournoi|tournament)\b"
    r"|(?:teste|tester|testez|test)\s*(?:mon|ce|my|this)\s*(?:jeu|game)\s*.{0,25}(?:stp|svp|please|plz)\b"
    r")",
    re.IGNORECASE,
)

# Extensions exécutables ou potentiellement dangereuses dans les pièces jointes
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".apk",
    ".com", ".pif", ".jar", ".msi", ".iso", ".ps1", ".hta", ".wsf",
}

# Mots-clés suspects dans les noms de fichiers attachés (ex: free_nitro_generator.zip)
SUSPICIOUS_FILENAME_KEYWORDS_RE = re.compile(
    r"(?:nitro|giftcard|steam_?gift|airdrop|generator|free_?nitro|crack|hack|token_?grabber)",
    re.IGNORECASE,
)

# Table de substitution homoglyphes cyrilliques et similaires
_HOMOGLYPH_TABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "u",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "U",
    "ᴀ": "a", "ɢ": "g", "ɪ": "i", "ɴ": "n", "ʀ": "r", "в": "b",
    "ǝ": "e", # e inversé
    "ο": "o", "ι": "i", "α": "a",  # grec courant
    "і": "i", "І": "I", "х": "x", "Х": "X", "ѕ": "s", "Ѕ": "S",
    "₀": "0", "°": "0",
})

# Historique glissant des messages récents par membre pour détecter les escroqueries découpées
_user_recent_messages: dict[tuple[int, int], list[tuple[float, discord.Message]]] = {}


def _normalize_variants(text: str) -> list[str]:
    """
    Génère des variantes normalisées pour contourner les évasions classiques :
    1. Texte original
    2. Homoglyphes remplacés (a cyrillique → a latin)
    3. Espaces isolés entre lettres supprimés (n i t r o -> nitro) sans fusionner les vrais mots
    4. Diacritiques retirés (é -> e)
    """
    variants = [text]
    trans = text.translate(_HOMOGLYPH_TABLE)
    if trans != text:
        variants.append(trans)
    # Effondrement des lettres isolées espacées (n i t r o -> nitro)
    collapsed = re.sub(r"(?<=\b[a-zA-Z0-9])\s+(?=[a-zA-Z0-9]\b)", "", trans)
    if collapsed not in variants:
        variants.append(collapsed)
    # Diacritiques
    de_accent = "".join(c for c in unicodedata.normalize("NFD", trans) if unicodedata.category(c) != "Mn")
    if de_accent not in variants:
        variants.append(de_accent)
    return variants


@dataclass
class ScamResult:
    is_scam: bool = False
    reasons: list[str] = field(default_factory=list)
    score: float = 0.0          # 0.0 → 1.0 : gravité estimée
    invite_links: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)


def analyze(
    content: str,
    *,
    allow_invites: bool = False,
    embeds: list[discord.Embed] | None = None,
    attachments: list[discord.Attachment] | None = None,
) -> ScamResult:
    """
    Analyse le contenu d'un message, ses embeds et ses pièces jointes/images.
    Retourne un ScamResult. Stateless — appelable sans I/O.
    """
    result = ScamResult()

    # Extraire texte et liens des embeds (titre, description, champs, footer, auteur)
    full_text = content or ""
    if embeds:
        embed_texts: list[str] = []
        for emb in embeds:
            for attr in ("title", "description", "url"):
                val = getattr(emb, attr, None)
                if val:
                    embed_texts.append(str(val))
            if getattr(emb, "author", None) and getattr(emb.author, "name", None):
                embed_texts.append(str(emb.author.name))
            if getattr(emb, "footer", None) and getattr(emb.footer, "text", None):
                embed_texts.append(str(emb.footer.text))
            for f in getattr(emb, "fields", []):
                if getattr(f, "name", None):
                    embed_texts.append(str(f.name))
                if getattr(f, "value", None):
                    embed_texts.append(str(f.value))
        if embed_texts:
            full_text = (full_text + " " + " ".join(embed_texts)).strip()

    # Analyse des pièces jointes et images
    if attachments:
        for att in attachments:
            fname = getattr(att, "filename", "") or ""
            # Description / Alt-text Discord
            desc = getattr(att, "description", None)
            if desc:
                full_text = (full_text + " " + str(desc)).strip()

            lower_fname = fname.lower()
            ext = os.path.splitext(lower_fname)[1]
            # Détection doubles extensions (ex: nitro.png.exe ou card.jpg.scr)
            has_double_ext = any(
                lower_fname.endswith(f"{img_ext}{bad_ext}")
                for img_ext in [".png", ".jpg", ".jpeg", ".gif", ".webp"]
                for bad_ext in DANGEROUS_EXTENSIONS
            )

            if ext in DANGEROUS_EXTENSIONS or has_double_ext:
                result.reasons.append(f"fichier attaché dangereux ({fname})")
                result.score = max(result.score, 0.90)
            elif SUSPICIOUS_FILENAME_KEYWORDS_RE.search(fname):
                result.reasons.append(f"nom de fichier suspect ({fname})")
                result.score = max(result.score, 0.70)

    if not full_text and not result.reasons:
        return result

    # 1. Invitations Discord
    if not allow_invites and full_text:
        invites = DISCORD_INVITE_RE.findall(full_text)
        if invites:
            result.invite_links = invites
            result.reasons.append(f"invitation Discord non autorisée ({len(invites)} lien(s))")
            result.score = max(result.score, 0.55)

    # 2. URLs suspectes
    if full_text:
        sus_urls = SUSPICIOUS_URL_RE.findall(full_text)
        if sus_urls:
            result.suspicious_urls = sus_urls
            result.reasons.append(f"URL suspecte/raccourcie ({len(sus_urls)} occurrence(s))")
            result.score = max(result.score, 0.65)

    # 3. Analyse lexicale multi-catégories
    raid_matches: list[str] = []
    kw_matches: list[str] = []
    money_matches: list[str] = []
    bio_matches: list[str] = []
    bio_invites: list[str] = []
    dm_matches: list[str] = []
    social_matches: list[str] = []

    if full_text:
        for var in _normalize_variants(full_text):
            if not raid_matches:
                raid_matches = RAID_THREAT_RE.findall(var)
            if not kw_matches:
                kw_matches = SCAM_KEYWORDS_RE.findall(var)
            if not money_matches:
                money_matches = MONEY_LURE_RE.findall(var)
            if not bio_matches:
                bio_matches = BIO_REDIRECT_RE.findall(var)
            if not bio_invites:
                bio_invites = BIO_INVITE_RE.findall(var)
            if not dm_matches:
                dm_matches = DM_LURE_RE.findall(var)
            if not social_matches:
                social_matches = SOCIAL_ENG_RE.findall(var)

    # Menace de raid / nuke / crash : score critique maximal immédiat
    if raid_matches:
        result.reasons.append(f"menace d'attaque / raid / sabotage : « {raid_matches[0].strip()} »")
        result.score = 1.0

    if kw_matches:
        result.reasons.append(f"pattern phishing détecté : « {kw_matches[0].strip()} »")
        result.score = max(result.score, 0.80)

    if money_matches:
        result.reasons.append(f"appât financier / promesse de gains : « {money_matches[0].strip()} »")
        result.score = max(result.score, 0.80)

    if bio_matches:
        result.reasons.append(f"incitation à cliquer sur un lien en bio / profil : « {bio_matches[0].strip()} »")
        result.score = max(result.score, 0.80)

    if bio_invites:
        result.reasons.append(f"publicité / invitation de serveur en bio : « {bio_invites[0].strip()} »")
        result.score = max(result.score, 0.85)

    if dm_matches:
        result.reasons.append(f"sollicitation suspecte en message privé : « {dm_matches[0].strip()} »")
        result.score = max(result.score, 0.75)

    if social_matches:
        result.reasons.append(f"ingénierie sociale suspecte : « {social_matches[0].strip()} »")
        result.score = max(result.score, 0.75)

    # Combinaisons de signaux cumulatifs
    if money_matches and (bio_matches or bio_invites):
        # Appât financier + redirection bio = tentative d'arnaque confirmée
        result.score = min(1.0, max(result.score, 0.85) + 0.10)

    if full_text and SUSPICIOUS_URL_RE.findall(full_text) and (kw_matches or money_matches or raid_matches):
        result.score = min(1.0, result.score + 0.15)

    result.is_scam = result.score >= 0.50
    return result


async def handle_message(
    message: discord.Message,
    *,
    allow_invites: bool = False,
    delete_message: bool = True,
    warn_in_channel: bool = True,
    bus=None,
    append_evidence=None,
) -> ScamResult:
    """
    Analyse le message (contenu, embeds, images/fichiers, et séquence multi-messages)
    et applique les actions si scam détecté.
    Retourne le ScamResult (is_scam=False si rien à signaler).

    À appeler depuis on_message, APRÈS le check canary et AVANT fingerprint.
    """
    guild = message.guild
    author = message.author
    channel = message.channel

    now = time.time()
    key = (guild.id, author.id)
    recent = _user_recent_messages.get(key, [])
    # Garde l'historique des messages des 60 dernières secondes
    recent = [(ts, m) for ts, m in recent if now - ts < 60]

    # 1. Analyse du message courant
    result = analyze(
        message.content,
        allow_invites=allow_invites,
        embeds=message.embeds,
        attachments=message.attachments,
    )

    # 2. Détection de répétition / flood identique (ex: même message envoyé 2 fois en moins de 15s)
    messages_to_clean: list[discord.Message] = []
    recent_identical = [
        m for ts, m in recent
        if now - ts < 20 and m.content and m.content.strip().lower() == message.content.strip().lower()
    ]
    if recent_identical and len(message.content.strip()) > 8:
        result.is_scam = True
        result.reasons.append("répétition rapide de message identique (spam/flood)")
        result.score = max(result.score, 0.85)
        messages_to_clean.extend(recent_identical)

    # 3. Si non flaggé individuellement, analyse le contexte combiné avec les messages récents du membre
    if not result.is_scam and recent:
        combined_text = "\n".join([m.content for _, m in recent if m.content] + [message.content])
        combined_res = analyze(combined_text, allow_invites=allow_invites)
        if combined_res.is_scam:
            result = combined_res
            messages_to_clean.extend([m for _, m in recent if m.channel.id == channel.id])

    if not result.is_scam:
        # Enregistre le message dans l'historique glissant de l'utilisateur (max 5)
        recent.append((now, message))
        _user_recent_messages[key] = recent[-5:]
        return result

    # ── Contenu suspect / menace détectée : purge et sanctions autonomes ───────
    _user_recent_messages[key] = []  # réinitialise l'historique de ce membre

    logger.warning(
        "Contenu suspect détecté de %s dans #%s (%s) — score=%.2f — raisons: %s",
        author, channel.name, guild.name, result.score, "; ".join(result.reasons),
    )

    # Sanction autonome : Timeout (mute) direct du membre sur Discord
    timeout_applied = False
    if isinstance(author, discord.Member):
        timeout_seconds = 3600 if result.score >= 0.95 else 600  # 1h si raid/nuke, sinon 10min
        try:
            await author.timeout(
                discord.utils.utcnow() + datetime.timedelta(seconds=timeout_seconds),
                reason=f"SENTINEL : {'; '.join(result.reasons[:2])}",
            )
            timeout_applied = True
            logger.warning("Timeout %ds appliqué automatiquement à %s sur %s", timeout_seconds, author, guild.name)
        except discord.Forbidden:
            logger.warning("Impossible de timeout %s (rôle hiérarchique supérieur ou propriétaire)", author)
        except discord.HTTPException as e:
            logger.warning("Erreur HTTP lors du timeout de %s : %s", author, e)

    # Suppression du message courant
    if delete_message:
        try:
            await message.delete()
        except discord.Forbidden:
            logger.error(
                "PERMISSION REFUSÉE : SENTINEL n'a pas la permission 'Gérer les messages' sur %s dans #%s !",
                guild.name, channel.name,
            )
            try:
                await channel.send(
                    f"⚠️ **SENTINEL** a détecté un contenu suspect de {author.mention} mais n'a pas la permission **Gérer les messages** pour le supprimer !\n"
                    "👉 **Donnez la permission 'Gérer les messages' ou 'Administrateur' au rôle de SENTINEL.**",
                    delete_after=20,
                )
            except Exception:
                pass
        except discord.HTTPException:
            pass

        # Suppression des messages préalables qui faisaient partie de l'arnaque découpée
        for prev_msg in messages_to_clean:
            try:
                await prev_msg.delete()
            except (discord.Forbidden, discord.HTTPException):
                pass

    # Avertissement public épinglé dans le salon
    if warn_in_channel:
        reasons_str = "\n".join(f"• {r}" for r in result.reasons)
        action_note = " — Membre réduit au silence 1h" if result.score >= 0.95 and timeout_applied else (
            " — Membre réduit au silence 10min" if timeout_applied else ""
        )
        try:
            await channel.send(
                f"🚨 {author.mention} — Message supprimé par **SENTINEL**{action_note} (contenu malveillant) :\n{reasons_str}",
                delete_after=30,  # auto-supprimé après 30s pour garder le salon propre
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    # Chaîne de preuves + bus si score critique
    if append_evidence:
        entry = await append_evidence(guild.id, "scam_detected", {
            "user_id": author.id,
            "author_name": str(author),
            "channel_id": channel.id,
            "score": result.score,
            "reasons": result.reasons,
            "invite_links": result.invite_links,
            "suspicious_urls": result.suspicious_urls,
            "content_snippet": message.content[:200],
        })
        if bus and result.score >= 0.80:
            await bus.emit("risk_critical", {
                "guild_id": guild.id,
                "user_id": author.id,
                "score": result.score,
                "reason": "scam_phishing_or_raid_threat",
                "signals": {"scam_score": result.score, "reasons": result.reasons},
                "evidence_hash": entry["hash"] if entry else "unhashed",
            })

    return result
