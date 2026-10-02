#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BIDABOT — Script d'Auto-Update Automatique (Polling Git)
# ═══════════════════════════════════════════════════════════════════════
# Vérifie s'il y a de nouveaux commits sur GitHub.
# S'il y a du nouveau, met à jour le code et redémarre le Bot et le Dashboard.
# ═══════════════════════════════════════════════════════════════════════

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

git fetch origin main > /dev/null 2>&1 || git fetch origin master > /dev/null 2>&1

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "$LOCAL")

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 Nouvelle mise à jour détectée ! Application..."
    git pull origin main || git pull origin master
    
    # Si les dépendances Python ou le Dockerfile ont changé, on reconstruit
    if git diff --name-only "$LOCAL" HEAD | grep -E -q "requirements.txt|Dockerfile"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📦 Nouvelles dépendances détectées, reconstruction Docker..."
        docker compose up -d --build bot dashboard federation_api
    else
        # Sinon, grâce aux volumes montés en direct, docker compose up -d applique immédiatement le nouveau code
        docker compose up -d bot dashboard
        docker compose restart bot dashboard
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Bidabot & Dashboard mis à jour avec succès !"
fi
