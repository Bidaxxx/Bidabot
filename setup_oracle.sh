#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# SENTINEL — Script d'installation & déploiement automatique Oracle Cloud
# ═══════════════════════════════════════════════════════════════════════
set -e

# Couleurs pour le terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   🛡️  SENTINEL — Déploiement Automatisé Oracle Cloud VM${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"

# 1. Vérification des privilèges
if [ "$EUID" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

echo -e "\n${YELLOW}[1/5] Mise à jour du système & Installation de Docker...${NC}"
$SUDO apt update -y
$SUDO apt install -y curl git ufw iptables-persistent netfilter-persistent

# Installation Docker si non présent
if ! command -v docker &> /dev/null; then
  echo -e "${BLUE}Installation du moteur Docker officiel...${NC}"
  curl -fsSL https://get.docker.com -o get-docker.sh
  $SUDO sh get-docker.sh
  rm -f get-docker.sh
  $SUDO usermod -aG docker $USER || true
else
  echo -e "${GREEN}Docker est déjà installé.${NC}"
fi

# Installation Docker Compose si plugin manquant
if ! docker compose version &> /dev/null; then
  echo -e "${BLUE}Installation du plugin Docker Compose...${NC}"
  $SUDO apt install -y docker-compose-plugin docker-compose
fi

echo -e "\n${YELLOW}[2/5] Déblocage des pare-feux Oracle Cloud (iptables & UFW)...${NC}"
# Oracle Cloud Ubuntu a des règles iptables restrictives par défaut qui bloquent le trafic entrant
$SUDO iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT || true
$SUDO iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT || true
$SUDO iptables -I INPUT 6 -m state --state NEW -p tcp --dport 8002 -j ACCEPT || true
$SUDO netfilter-persistent save || true

# Configuration UFW si activé
$SUDO ufw allow 22/tcp || true
$SUDO ufw allow 80/tcp || true
$SUDO ufw allow 443/tcp || true
$SUDO ufw allow 8002/tcp || true

echo -e "\n${YELLOW}[3/5] Vérification de la configuration d'environnement (.env)...${NC}"
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    echo -e "${GREEN}Fichier .env créé depuis .env.example.${NC}"
  else
    echo -e "${RED}Erreur : .env.example introuvable.${NC}"
    exit 1
  fi
fi

# Création du dossier models s'il n'existe pas
mkdir -p models

# Vérification du token Discord dans .env
if grep -q "COLLE_TON_TOKEN_ICI" .env; then
  echo -e "\n${RED}⚠️ ATTENTION : Ton token Discord n'est pas encore configuré !${NC}"
  echo -e "Édite le fichier avec : ${YELLOW}nano .env${NC} et remplace COLLE_TON_TOKEN_ICI par ton vrai token Discord."
  read -p "Souhaites-tu entrer ton token Discord maintenant ? (o/n) : " REP
  if [[ "$REP" =~ ^[oOyY]$ ]]; then
    read -p "Colle ton token Discord : " BOT_TOKEN
    if [ -n "$BOT_TOKEN" ]; then
      sed -i "s|DISCORD_TOKEN=.*|DISCORD_TOKEN=$BOT_TOKEN|g" .env
      echo -e "${GREEN}Token mis à jour avec succès dans .env !${NC}"
    fi
  fi
fi

echo -e "\n${YELLOW}[4/5] Lancement des conteneurs Sentinel (PostgreSQL pgvector, Redis, Bot, Dashboard)...${NC}"
$SUDO docker compose up -d --build

# Configuration de la mise à jour automatique en arrière-plan (toutes les 2 minutes)
chmod +x auto_update.sh
(crontab -l 2>/dev/null | grep -F "auto_update.sh") || (crontab -l 2>/dev/null; echo "*/2 * * * * $(pwd)/auto_update.sh >> /var/log/sentinel_autoupdate.log 2>&1") | crontab -
echo -e "${GREEN}🔄 Mise à jour automatique configurée (vérification toutes les 2 min).${NC}"

echo -e "\n${YELLOW}[5/5] Récupération de l'adresse IP publique de la machine...${NC}"
PUB_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "IP_DE_TON_SERVEUR")

echo -e "\n${GREEN}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎉 SENTINEL EST DÉPLOYÉ AVEC SUCCÈS SUR ORACLE CLOUD !${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════════════════════${NC}"
echo -e "\n🌐 ${BLUE}Accès au site web & explorateur de commandes (Style DraftBot) :${NC}"
echo -e "   👉 ${GREEN}http://${PUB_IP}/${NC}  ou  ${GREEN}http://${PUB_IP}:8002/${NC}"
echo -e "\n🛡️  ${BLUE}Console d'administration Staff :${NC}"
echo -e "   👉 ${GREEN}http://${PUB_IP}/dashboard${NC}"
echo -e "   🔑 Mot de passe : configuré dans ton fichier .env (DASHBOARD_PASSWORD)"
echo -e "\n📊 ${BLUE}Commandes utiles :${NC}"
echo -e "   • Voir les logs du bot en direct :  ${YELLOW}sudo docker compose logs -f bot${NC}"
echo -e "   • Voir les logs du site/dashboard : ${YELLOW}sudo docker compose logs -f dashboard${NC}"
echo -e "   • Redémarrer tout le système :      ${YELLOW}sudo docker compose restart${NC}"
echo -e "   • Arrêter le système :              ${YELLOW}sudo docker compose down${NC}"
echo -e "\n${YELLOW}💡 Rappel Oracle Cloud : N'oublie pas d'ajouter les ports 80 et 8002 dans la Security List de ton VCN Oracle !${NC}\n"
