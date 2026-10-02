"""
Module 7 — Moteur forensique.

Chaîne de hash SHA-256 (chaque preuve référence le hash de la précédente),
signée Ed25519 par le bot à la génération du rapport PDF final -> deux
garanties distinctes :
- intégrité de la chaîne (verify_chain) : aucune preuve n'a été altérée
  ou retirée après coup.
- authenticité du rapport (verify_signature) : CE rapport a bien été
  produit par CE bot, avec SA clé privée (jamais exposée).
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from bot.crypto_utils import compute_chain_hash, sign_bytes, canonical_json


async def append_evidence(db, guild_id: int, event_type: str, data: dict) -> dict[str, Any]:
    prev_hash = await db.last_evidence_hash(guild_id)
    ts = datetime.now(timezone.utc).isoformat()
    h = compute_chain_hash(prev_hash, event_type, data, ts)
    await db.insert_evidence(guild_id, event_type, data, h, prev_hash, signature="", ts=ts)
    return {"event_type": event_type, "hash": h, "prev_hash": prev_hash, "timestamp": ts, "data": data}


async def verify_chain(db, guild_id: int) -> tuple[bool, int]:
    rows = await db.fetch_evidence_chain(guild_id)
    prev = None
    for r in rows:
        import json
        data = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
        # On réutilise ts_iso, la chaîne EXACTE utilisée au moment du calcul du
        # hash d'origine — jamais r["ts"] (datetime reformaté par asyncpg, qui
        # pourrait différer du texte source et casser la vérification à tort).
        expected = compute_chain_hash(prev, r["event_type"], data, r["ts_iso"])
        if expected != r["hash"]:
            return False, r["id"]
        prev = r["hash"]
    return True, len(rows)


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SentinelTitle", fontSize=18, spaceAfter=12, textColor=colors.HexColor("#1a1a2e")))
    styles.add(ParagraphStyle(name="SentinelMeta", fontSize=9, textColor=colors.grey))
    styles.add(ParagraphStyle(name="SentinelHash", fontName="Courier", fontSize=7))
    return styles


def build_pdf_report(guild_name: str, guild_id: int, evidence_rows: list, chain_valid: bool,
                      signing_key: Ed25519PrivateKey) -> bytes:
    # On signe un DIGEST des données sources (pas les octets du PDF final) :
    # signer le PDF rendu créerait un problème circulaire (le PDF devrait
    # contenir sa propre signature, donc changer, donc invalider la
    # signature qu'il contient). Le digest, lui, ne dépend que du contenu
    # vérifiable — la mise en page peut changer sans invalider la preuve.
    generated_at = datetime.now(timezone.utc).isoformat()
    digest_payload = canonical_json({
        "guild_id": guild_id,
        "generated_at": generated_at,
        "chain_valid": chain_valid,
        "evidence_hashes": [r["hash"] for r in evidence_rows],
    })
    signature = sign_bytes(signing_key, digest_payload)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = _styles()
    story = []

    story.append(Paragraph("SENTINEL — Rapport forensique", styles["SentinelTitle"]))
    story.append(Paragraph(
        f"Serveur : {guild_name} ({guild_id}) — Généré le {generated_at}", styles["SentinelMeta"],
    ))
    story.append(Paragraph(
        f"Intégrité de la chaîne : {'✅ VALIDE' if chain_valid else '❌ CORROMPUE — voir alerte immédiate'}",
        styles["SentinelMeta"],
    ))
    story.append(Spacer(1, 10 * mm))

    table_data = [["#", "Type d'événement", "Horodatage", "Hash (16 premiers car.)"]]
    for i, r in enumerate(evidence_rows, start=1):
        table_data.append([str(i), r["event_type"], str(r["ts"]), r["hash"][:16] + "…"])

    table = Table(table_data, colWidths=[15 * mm, 45 * mm, 55 * mm, 50 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f7")]),
    ]))
    story.append(table)

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        "Signature Ed25519 du digest ci-dessus (guild_id + horodatage + validité de chaîne "
        "+ liste ordonnée des hashes). Se vérifie indépendamment du rendu PDF :",
        styles["SentinelMeta"],
    ))
    story.append(Paragraph(signature, styles["SentinelHash"]))

    doc.build(story)
    return buf.getvalue()
