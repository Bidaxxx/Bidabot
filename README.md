# SENTINEL

Bot Discord de sécurité communautaire — architecture "système immunitaire de
serveur" : chaque module alimente les autres, un incident déclenche une
réponse orchestrée avec preuves à l'appui.

Implémente les 9 modules du rapport d'architecture, avec la stack demandée :
`discord.py`, `scikit-learn`, `PostgreSQL + pgvector`, `Redis`, `FastAPI`
(fédération HMAC + dashboard HTMX), `ReportLab` (PDF), `cryptography`
(signature Ed25519).

## Arborescence

```
bot/
  config.py            Configuration (env)
  db.py                 Accès PostgreSQL/pgvector
  cache.py              Fenêtres glissantes Redis
  bus.py                Bus d'événements interne (dispatch séquentiel)
  crypto_utils.py        Hash chain, signature Ed25519, HMAC fédération
  main.py                Point d'entrée, câblage des event handlers Discord
  modules/
    legitimacy.py        Module 3 — score (bayésien cold-start -> scikit-learn)
    lockdown.py           Module 3bis — lockdown auto (dry-run + override)
    fingerprint.py         Module 1 — vecteur comportemental 16D
    stylometry.py           Module 2 — signature de style 64D (hashing trick)
    coordination.py          Module 4 — détection de raid coordonné
    canary.py                  Module 5 — canaux pièges + liens honeytoken
    credential_stuffing.py      Module 6 — rate-limit + rotation webhook
    forensics.py                  Module 7 — chaîne de hash + PDF signé
    federation_client.py           Module 8 — client HMAC vers federation_api
    warroom.py                      Module 9 — war room auto-assemblée
  cogs/admin.py            Commandes /sentinel …
federation_api/app.py    Service FastAPI : fédération + endpoint honeytoken
dashboard/app.py         Dashboard modérateur FastAPI + HTMX
ml/train_legitimacy.py   Ré-entraînement offline du modèle scikit-learn
schema.sql               Schéma PostgreSQL complet (pgvector)
docker-compose.yml        Postgres+pgvector, Redis, bot, API, dashboard
tests/                     Tests de la logique pure (voir plus bas)
```

## Déploiement Gratuit à Vie (Oracle Cloud Always Free)

Sentinel est 100% optimisé pour tourner gratuitement 24h/24 sur une machine **Oracle Cloud Always Free** (4 vCPU ARM, 24 Go de RAM, IP fixe gratuite) :

```bash
# Sur votre serveur Ubuntu Oracle Cloud :
git clone https://github.com/VOTRE_UTILISATEUR/sentinel.git
cd sentinel/sentinel
chmod +x setup_oracle.sh
./setup_oracle.sh
```

Consultez le guide détaillé : `guide_deploiement_oracle_cloud.md`.

## Démarrage rapide en local (Docker)

```bash
cp .env.example .env
# Édite .env avec ton token Discord
docker compose up -d --build
```

Sur le portail développeur Discord, activez les **privileged intents** :
`SERVER MEMBERS INTENT` et `MESSAGE CONTENT INTENT`.

- **Site Web Public (Style DraftBot) :** http://localhost/ ou http://localhost:8002/
- **Console Modérateur Staff :** http://localhost/dashboard (mot de passe = `DASHBOARD_PASSWORD`)
- **API fédération :** http://localhost:8001/health


## Flux anti-raid (tel qu'implémenté)

```
join détecté
  -> vélocité (Redis, fenêtre glissante) + score de légitimité (module 3)
  -> si score >= seuil critique :
       événement "risk_critical" traité SÉQUENTIELLEMENT (bus.py) :
       1. lockdown (3bis) — ou simulation si guilds.dry_run = true
       2. war room (9) — embed enrichi des comptes proches (modules 1 et 2)
  -> après chaque rafale de joins : vérification de coordination (module 4)
     -> si cluster détecté : "risk_critical" à nouveau, même chaîne

message dans un canal piège -> "canary_hit" -> war room directe (module 5)
clic sur lien honeytoken -> logué par federation_api, PAS par le bot

chaque étape ci-dessus s'ajoute à la chaîne forensique (module 7),
consultable/vérifiable via /sentinel verify et exportable en PDF signé
via /sentinel report.
```

## Garde-fous mis en place (points légaux de l'architecture)

- **Mode dry-run par défaut** (`guilds.dry_run = TRUE`) : le lockdown est
  entièrement calculé et loggé, mais aucune permission n'est réellement
  modifiée tant qu'un admin n'a pas fait `/sentinel dry-run off`.
- **Override humain immédiat** : `/sentinel lockdown off` répond toujours
  tout de suite, y compris pendant une fenêtre d'auto-release en attente.
- **Aucune IP en clair** : toujours `HMAC-SHA256(ip, HASH_PEPPER)`
  (canary, credential-stuffing) ou `HMAC-SHA256(discord_id, FEDERATION_PEPPER)`
  (fédération) — jamais l'identifiant brut hors de la base du serveur
  d'origine.
- **Fédération opt-in explicite** : aucun envoi automatique — un partenaire
  n'existe en base que si un admin l'a ajouté manuellement
  (`federation_partners`), avec son propre secret HMAC.
- **Liens honeytoken** : `/sentinel canary link` rappelle à chaque
  génération que le règlement du serveur doit mentionner l'usage de liens
  de détection d'intrusion avant toute utilisation (transparence RGPD).
- **Chaîne forensique vérifiable indépendamment** : la signature Ed25519
  du rapport PDF porte sur un digest des données sources (guild_id,
  horodatage, liste des hashes), pas sur les octets du PDF rendu — évite
  le problème circulaire d'un document qui devrait contenir sa propre
  signature valide.

Ces garde-fous réduisent le risque mais ne remplacent pas la conformité :
avant toute activation en production sur un serveur avec de vrais membres,
fais relire la configuration (fingerprinting, stylométrie, canary) par
quelqu'un qui peut engager la responsabilité du serveur — l'architecture
d'origine liste "intérêt légitime de modération" comme base légale RGPD à
documenter dans le règlement, pas comme une autorisation automatique.

## Modèle de légitimité (module 3)

Cold start : combinaison bayésienne des 4 signaux (âge du compte, avatar
par défaut, vélocité de join, rafale de messages). Dès que
`LEGITIMACY_MIN_TRAINING_SAMPLES` labels existent (via `/sentinel label
<membre> raid|legit`) et que les deux classes sont représentées,
`/sentinel train` (ou `python -m ml.train_legitimacy`) entraîne une
régression logistique scikit-learn et la charge à chaud — le score reste
toujours accompagné de son `breakdown` et de son `model_version` en base,
pour rester explicable.

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

Les tests couvrent la logique pure (chaîne de hash, scoring bayésien,
signature/vérification Ed25519 et HMAC, features de stylométrie) sans
nécessiter de connexion Postgres/Redis/Discord — voir `tests/`.

## Priorisation suggérée pour la mise en prod

1. Modules 3 + 7 (légitimité + forensique) — valeur immédiate, faible risque
2. Module 5 (canary channels, sans les liens honeytoken au départ)
3. Module 1 (fingerprint) puis module 9 (war room)
4. Modules 2, 4, 6 (raffinements)
5. Module 8 (fédération) — seulement une fois le reste stable, implique
   un accord RGPD écrit avec chaque serveur partenaire
