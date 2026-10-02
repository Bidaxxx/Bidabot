#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BIDABOT — Script d'Auto-Update Automatique (Polling Git)
# ═══════════════════════════════════════════════════════════════════════
# Vérifie s'il y a de nouveaux commits sur GitHub.
# S'il y a du nouveau, met à jour le code et redémarre le Bot et le Dashboard.
# ═══════════════════════════════════════════════════════════════════════

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

git fetch origin main > /dev/null 2>&1

LOCAL=$(git rev-parse HEAD 2>/dev/null)
REMOTE=$(git rev-parse origin/main 2>/dev/null)

if [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 Nouvelle mise à jour détectée ($LOCAL -> $REMOTE) ! Application..."
    git checkout -B main origin/main
    git reset --hard origin/main
    
    # Si les dépendances Python ou le Dockerfile ont changé, on reconstruit
    if git diff --name-only "$LOCAL" "$REMOTE" 2>/dev/null | grep -E -q "requirements.txt|Dockerfile"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📦 Nouvelles dépendances détectées, reconstruction Docker..."
        docker compose up -d --build bot dashboard federation_api
    else
        # Grâce aux volumes montés en direct, un redémarrage suffit
        docker compose up -d bot dashboard
        docker compose restart bot dashboard
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Bidabot & Dashboard mis à jour avec succès !"
fi

