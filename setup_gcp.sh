#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BIDABOT — Script d'installation & déploiement Google Cloud (Always Free)
# ═══════════════════════════════════════════════════════════════════════
set -e

# Couleurs pour le terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   🛡️  BIDABOT — Déploiement Google Cloud Always Free (e2-micro)${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"

if [ "$EUID" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

# 1. Configuration de la mémoire SWAP (Essentiel sur e2-micro 1 Go RAM)
echo -e "\n${YELLOW}[1/5] Optimisation mémoire (création swap 3 Go pour l'e2-micro)...${NC}"
if ! swapon --show | grep -q "/swapfile"; then
  echo -e "${BLUE}Activation du fichier swap...${NC}"
  $SUDO fallocate -l 3G /swapfile || $SUDO dd if=/dev/zero of=/swapfile bs=1M count=3072
  $SUDO chmod 600 /swapfile
  $SUDO mkswap /swapfile
  $SUDO swapon /swapfile
  echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab
  echo -e "${GREEN}Mémoire swap de 3 Go activée avec succès.${NC}"
else
  echo -e "${GREEN}Fichier swap déjà actif.${NC}"
fi

# 2. Mise à jour et Docker
echo -e "\n${YELLOW}[2/5] Installation de Docker & Docker Compose...${NC}"
$SUDO apt update -y
$SUDO apt install -y curl git ufw

if ! command -v docker &> /dev/null; then
  echo -e "${BLUE}Installation du moteur Docker officiel...${NC}"
  curl -fsSL https://get.docker.com -o get-docker.sh
  $SUDO sh get-docker.sh
  rm -f get-docker.sh
  $SUDO usermod -aG docker $USER || true
else
  echo -e "${GREEN}Docker est déjà installé.${NC}"
fi

if ! docker compose version &> /dev/null; then
  $SUDO apt install -y docker-compose-plugin docker-compose || true
fi

# 3. Configuration environnement
echo -e "\n${YELLOW}[3/5] Configuration du fichier .env...${NC}"
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    echo -e "${GREEN}Fichier .env créé depuis .env.example.${NC}"
  fi
fi

mkdir -p models

if grep -q "COLLE_TON_TOKEN_ICI" .env 2>/dev/null; then
  echo -e "\n${YELLOW}Configuration du Token Discord :${NC}"
  read -p "Colle ton token Discord (ou appuie sur Entrée pour le faire plus tard) : " BOT_TOKEN
  if [ -n "$BOT_TOKEN" ]; then
    sed -i "s|DISCORD_TOKEN=.*|DISCORD_TOKEN=$BOT_TOKEN|g" .env
    echo -e "${GREEN}Token enregistré dans .env !${NC}"
  fi
fi

# 4. Lancement des conteneurs
echo -e "\n${YELLOW}[4/5] Lancement des conteneurs Bidabot...${NC}"
$SUDO docker compose up -d --build

# 5. Configuration de l'auto-update automatique
echo -e "\n${YELLOW}[5/5] Configuration de la mise à jour continue (CI/CD 2 min)...${NC}"
chmod +x auto_update.sh
SCRIPT_PATH="$(pwd)/auto_update.sh"
(crontab -l 2>/dev/null | grep -F "auto_update.sh") || (crontab -l 2>/dev/null; echo "*/2 * * * * /bin/bash $SCRIPT_PATH >> /var/log/bidabot_autoupdate.log 2>&1") | crontab -
echo -e "${GREEN}🔄 Auto-update actif : vérification GitHub automatique toutes les 2 minutes.${NC}"

# Récupération IP
PUB_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "IP_DE_TON_SERVEUR")

echo -e "\n${GREEN}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎉 BIDABOT EST EN LIGNE SUR GOOGLE CLOUD (100% GRATUIT) !${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════════════════════${NC}"
echo -e "• Dashboard Modérateur : ${BLUE}http://${PUB_IP}/dashboard${NC}"
echo -e "• Site Public           : ${BLUE}http://${PUB_IP}/${NC}"
echo -e "• Vérification Docker   : ${YELLOW}docker compose ps${NC}"
echo -e "• Logs du bot en direct : ${YELLOW}docker compose logs -f bot${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
