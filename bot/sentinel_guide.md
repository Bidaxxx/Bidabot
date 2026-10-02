# 🛡️ SENTINEL — Guide d'utilisation complet

## C'est quoi SENTINEL ?

Un **bot de sécurité autonome** pour Discord. Là où les bots classiques (MEE6, Carl-bot) appliquent des règles fixes ("si le message contient ce mot → supprimer"), SENTINEL **analyse les comportements** pour détecter les menaces que les règles statiques ratent.

C'est le "système immunitaire" de ton serveur :
- Il apprend ce qu'est un membre normal
- Il détecte les écarts par rapport à la normale
- Il agit avant que le dégât soit fait

---

## Ce qu'il fait automatiquement (sans que tu touches à rien)

### 🔍 Analyse de chaque nouveau membre
Dès qu'un compte rejoint, il calcule un **score de risque 0→1** basé sur :

| Signal | Explication |
|---|---|
| Âge du compte | Un compte créé hier = suspect |
| Avatar par défaut | Les bots/raids n'ont souvent pas d'avatar |
| Vélocité de join | 20 personnes en 1 minute = raid |
| Similarité comportementale | Même façon de taper que d'autres comptes récents |

### 🧠 Apprentissage continu (ML)
- Il s'entraîne automatiquement sur les bans ("raid") et les membres de longue date ("legit")
- Après ~50 labels, il passe du filtre Bayes à un modèle scikit-learn personnalisé pour ton serveur

### 🚨 Réactions automatiques selon le score

```
Score < 0.4  → Normal — rien
Score 0.4–0.7 → Suspect — logué en silence
Score > 0.7  → CRITIQUE → lockdown + war room ouverte
```

### 🔒 Lockdown intelligent
Quand une menace critique est détectée :
- Tous les salons passent en lecture seule pour les nouveaux membres
- Une **war room privée** (`#warroom-XXXXXX`) est créée pour les mods
- La timeline de l'incident s'affiche en temps réel dans la war room
- Quand le lockdown est levé, la war room se ferme automatiquement

### 📬 Audit des invitations
- Identifie quel lien d'invitation chaque membre a utilisé
- Si 70%+ des joiners récents viennent du même lien → alerte
- Si 85%+ → **révocation automatique** du lien

### 🔎 Détection de bannis qui reviennent
- Quand tu bans quelqu'un, son "empreinte comportementale" est conservée 90 jours
- Si un nouveau compte arrive avec le même style d'écriture + comportement → alerte immédiate

### 💬 Anti-scam / Anti-spam (en temps réel)
- Détecte les liens de phishing, faux Nitro, escroqueries crypto, invitations suspectes
- Supprime le message automatiquement + avertit l'utilisateur
- Après 3 avertissements antispam → action automatique

---

## Installation (1 fois)

### 1. Prérequis
```
PostgreSQL + extension pgvector
Redis
Python 3.12+
Un token de bot Discord
```

### 2. Configuration
Édite [`bot/config.py`](file:///c:/Users/2653474/Desktop/sentinel/sentinel/bot/config.py) :
```python
DISCORD_TOKEN = "ton-token-ici"
DATABASE_URL = "postgresql://user:pass@localhost/sentinel"
REDIS_URL = "redis://localhost:6379"
```

### 3. Base de données
```bash
psql -d sentinel -f schema.sql
psql -d sentinel -f migrations/001_add_guild_columns_and_indexes.sql
psql -d sentinel -f migrations/002_add_dashboard_and_security_modules.sql
psql -d sentinel -f migrations/003_modules_14_to_17.sql
```

### 4. Lancer le bot
```bash
cd sentinel/
python -m bot.main
```

### 5. Sur Discord — configuration initiale
```
/sentinel setup
```
→ Crée les catégories, canaux et rôles nécessaires. **À faire une seule fois par serveur.**

---

## Les commandes `/sentinel`

### 🔧 Configuration
| Commande | Qui | Action |
|---|---|---|
| `/sentinel setup` | Admin | Configuration initiale (war rooms, canary, dashboard) |
| `/sentinel dry-run on/off` | Admin | Mode simulation (analyse sans agir) — activer pendant les tests |

### 📊 Informations
| Commande | Qui | Action |
|---|---|---|
| `/sentinel status` | Admin | Vue d'ensemble : lockdown, incidents, score moyen |
| `/sentinel trustscore` | Tout le monde | Score de confiance du serveur 0→100 avec breakdown |
| `/sentinel whois [membre]` | Soi-même / Admin | Rapport complet sur un membre (score, incidents, forensique) |
| `/sentinel logs [#salon]` | Admin | Logs forensiques d'un salon avec filtres par type |
| `/sentinel invites` | Admin | Top des liens d'invitation + liens flaggués |

### 🔒 Contrôle d'accès
| Commande | Qui | Action |
|---|---|---|
| `/sentinel lockdown on` | Admin | Lockdown manuel immédiat |
| `/sentinel lockdown off` | Admin | Lever le lockdown |
| `/sentinel quarantine <membre>` | Admin | Isoler un membre dans `#sentinel-quarantine` |
| `/sentinel unquarantine <membre>` | Admin | Lever la quarantaine (ou bannir avec `ban:True`) |

### 🧠 ML & Labels
| Commande | Qui | Action |
|---|---|---|
| `/sentinel label <membre> raid/legit` | Admin | Corriger le modèle manuellement |
| `/sentinel train` | Admin | Réentraîner le modèle immédiatement |
| `/sentinel similar <membre>` | Admin | Voir les comptes au comportement proche |

### 🕵️ Investigation
| Commande | Qui | Action |
|---|---|---|
| `/sentinel verify` | Admin | Vérifie l'intégrité de la chaîne forensique |
| `/sentinel report` | Admin | Génère le rapport PDF signé (preuve légale) |
| `/sentinel federation check <membre>` | Admin | Signalements venant d'autres serveurs SENTINEL |

### 🎣 Canary (pièges)
| Commande | Qui | Action |
|---|---|---|
| `/sentinel canary setup` | Admin | Crée les canaux pièges invisibles |
| `/sentinel canary link` | Admin | Génère un lien honeytoken |

### 🛡️ Anti-scam (test)
| Commande | Qui | Action |
|---|---|---|
| `/sentinel scamcheck <texte>` | Admin | Teste le détecteur de scam sur un texte |

### 🎙️ Anti-Stresseur Vocal
| Commande | Qui | Action |
|---|---|---|
| `/sentinel voice renew [ch] [region]` | Admin | Recrée un salon vocal lagué/stressé et déplace automatiquement tous les membres |
| `/sentinel voice ping [ch]` | Tout le monde | Mesure la latence WebRTC et diagnostique la qualité du salon vocal |
| `/sentinel voice autoprotect <ch> [ping]` | Admin | Active l'auto-réparation automatique en cas de ping élevé ou de flood |
| `/sentinel voice region <ch> <region>` | Admin | Change la région vocale Discord (rotterdam, frankfurt, madrid...) |

### 💾 Sauvegardes & Restauration (Disaster Recovery)
| Commande | Qui | Action |
|---|---|---|
| `/sentinel backup create [label]` | Admin | Capture un snapshot complet de la structure (salons, rôles, permissions) |
| `/sentinel backup list` | Admin | Affiche la liste des sauvegardes disponibles avec ID et horodatage |
| `/sentinel backup restore <id>` | Admin | Restaure chirurgicalement tous les salons et rôles supprimés sans écraser l'existant |
| `/sentinel backup delete <id>` | Admin | Supprime définitivement un snapshot obsolète |

---

## Ce que le bot détecte (les 23 modules de pointe)

```
Module  1 — Fingerprint comportemental (pgvector)
Module  2 — Stylométrie (façon d'écrire)
Module  3 — Score de légitimité ML (Bayes → scikit-learn)
Module  4 — Coordination de raid (comptes similaires arrivant ensemble)
Module  5 — Canary channels (pièges qui alertent si accédés)
Module  6 — Credential stuffing (tentatives de connexion suspectes)
Module  7 — Chaîne forensique (preuves infalsifiables, signées Ed25519)
Module  8 — Fédération inter-serveurs (partage de signalements)
Module  9 — War room (centre de commandement d'incident & boutons d'urgence)
Module 10 — Anti-spam (burst de messages, répétitions)
Module 11 — Anti-scam (phishing, faux Nitro, crypto scams, masquage typographique)
Module 12 — Dashboard Discord (salons de statut et d'alertes temps réel)
Module 13 — Noms similaires (comptes qui imitent des mods / homoglyphes)
Module 14 — Quarantaine (isolation ciblée et réversible)
Module 15 — Trust score (score de santé global du serveur 0-100)
Module 16 — Ban fingerprints (détection de récidive sous nouveau compte)
Module 17 — Audit d'invitations (traçabilité des liens de raid)
Module 18 — Anti-Nuke, Anti-Rogue Bot & Webhooks malveillants
Module 19 — Anti-Impersonation avancé (bio, avatars, pseudos trompeurs)
Module 20 — Anti-Ghostping (journalisation & alertes de mentions furtives)
Module 21 — Console Web SaaS & Dashboard HTMX réactif (temps réel Redis Pub/Sub)
Module 22 — Anti-Stresseur Vocal & Surveillance de Passerelle WebRTC
Module 23 — Disaster Recovery & Restauration Instantanée 1-Clic (Snapshots)
```

---

## Schéma d'une attaque typique gérée par SENTINEL

```
🏴 Raid de 15 comptes créés hier
         │
         ▼
   on_member_join ×15 en 45s
         │
         ├─ Vélocité = 15 → SUSPECT
         ├─ Âge moyen = 0.3 jours → SUSPECT  
         ├─ Coordination: 13/15 vecteurs similaires → CRITIQUE
         └─ 12/15 viennent du même lien d'invitation
                   │
                   ▼
         🔴 bus.emit("risk_critical")
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
   🔒 LOCKDOWN          🚪 WAR ROOM
   Tous les salons       #warroom-a3f7 créé
   en lecture seule      Timeline en direct
         │                   │
         │            Admin décide :
         │            /sentinel lockdown off
         │            /sentinel quarantine @suspect1
         │            /sentinel label @suspect1 raid
         ▼
   ✅ Lockdown levé
   War room archivée
   Rapport PDF signé disponible
```

---

## Permissions Discord requises pour le bot

| Permission | Pourquoi |
|---|---|
| `Administrator` | Recommandé — simplifie tout |
| Ou à minima : | |
| `Manage Channels` | Créer war rooms, salon quarantaine |
| `Manage Roles` | Rôle quarantaine |
| `Manage Guild` | Lire + révoquer les invitations |
| `Ban Members` | Bans automatiques |
| `Kick Members` | Quarantaine → ban |
| `Manage Messages` | Supprimer les messages scam |
| `Send Messages` | Répondre dans les salons |

---

## Notes importantes

> [!WARNING]
> Lance toujours en **dry-run** la première semaine (`/sentinel dry-run on`).
> Le bot analyse mais n'agit pas. Tu peux voir les alertes sans risquer de lockdown accidentel.

> [!IMPORTANT]
> La migration SQL `003` est nécessaire pour les modules 14-17 (quarantaine, trust score, ban fingerprints, audit invitations). Sans elle, le bot crashera au démarrage.

> [!TIP]
> Le trust score monte naturellement avec le temps. Un serveur de moins de 6 mois commencera autour de 55/100. Utilise `/sentinel trustscore` pour voir ce qui plombe le score.
