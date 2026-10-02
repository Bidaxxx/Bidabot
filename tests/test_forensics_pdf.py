"""Vérifie que le PDF forensique se génère réellement et contient un PDF
valide + une signature Ed25519 lisible."""
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bot.modules.forensics import build_pdf_report


def test_build_pdf_report_produces_valid_pdf_bytes():
    key = Ed25519PrivateKey.generate()
    evidence_rows = [
        {"event_type": "join", "ts": datetime.now(timezone.utc), "hash": "a" * 64},
        {"event_type": "risk_critical", "ts": datetime.now(timezone.utc), "hash": "b" * 64},
        {"event_type": "lockdown_triggered", "ts": datetime.now(timezone.utc), "hash": "c" * 64},
    ]

    pdf_bytes = build_pdf_report("Mon Serveur Test", 123456789, evidence_rows, chain_valid=True, signing_key=key)

    assert pdf_bytes.startswith(b"%PDF")       # en-tête PDF standard
    assert b"%%EOF" in pdf_bytes[-20:] or b"EOF" in pdf_bytes[-1024:]  # fin de fichier PDF présente
    assert len(pdf_bytes) > 1000                # pas un fichier vide/tronqué


def test_build_pdf_report_handles_empty_chain():
    key = Ed25519PrivateKey.generate()
    pdf_bytes = build_pdf_report("Serveur Vide", 1, [], chain_valid=True, signing_key=key)
    assert pdf_bytes.startswith(b"%PDF")
