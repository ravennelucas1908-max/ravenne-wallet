# Ravenne UI — shell desktop (Tauri v2) · décisions et mode d'emploi

## Ce que c'est

Un shell desktop qui ** enveloppe sans jamais modifier** le CLI `ravenne.js` :

```
lancement → instance unique → (1re fois : config propriétaire) →
gate HWID (verrou machine) → choix de mode →
  ├─ Terminal  : ouvre cmd/K sur le CLI (dist\ravenne.exe en prod, node ravenne.js en dev)
  └─ Application : mot de passe → UI wallet (même vault.ravenne.json que le CLI)
```

## Compatibilité vault — la règle d'or

Le GUI ne lit/écrit le coffre **qu'au travers des mêmes primitives** que le CLI :

- **Gate** (`access.ravenne.json`) : scrypt(N=16384, r=8, p=1, 32 octets) comparé en temps constant —
  crate `scrypt` (RustCrypto), identique à `node:crypto.scryptSync`.
- **Vault** (`vault.ravenne.json`, format v7) : AES-256-GCM, tag séparé hex, data base64 —
  crates `aes-gcm` + `scrypt`, champ par champ identique à `ravenne.js`.
- Test d'interopérabilité : `vault_unlock` déverrouille le vault **créé par le CLI** et
  `vault_write_encrypted` produit un fichier que `decryptVault` du CLI rouvre (aucune migration).

Le unlock renvoie le JSON déchiffré au webview (même domaine de confiance que l'ancien
`index.html` qui gardait les clés côté JS). Les envois EVM utilisent ethers v6 côté UI,
exactement comme l'ancienne maquette. Aucune clé ne quitte la machine.

## Verrou machine (HWID) — barrière de confort, pas de la crypto

- Empreinte = `SHA-256(salt_statique + MachineGuid + série carte mère + série disque système)`.
  Requêtes : registre Windows (`reg query`) + PowerShell `Get-CimInstance` — pas de crate WMI
  (moins de dépendances, même fiabilité, timeouts bornés).
- `authorized.flag` à côté du vault : présent → **plus jamais** de re-vérification (silencieux).
- Whitelist = gist secret brut `{"machines":[{"id":"<sha256>","label":"…"}]}` ;
  cache local `.whitelist-cache.json` pour les démarrages hors ligne (machine inconnue reste bloquée).
- Webhook Discord : embeds (titre, champ Label/Machine/User/OS/HWID, footer « Ravenne Gate »,
  timestamp) — vert **une seule fois** (au premier flag), rouge à chaque tentative refusée.
- `ui.config.json` (webhook + gist + repo) jamais commité → `ui.config.example.json` sert de modèle.

## Choix techniques documentés

| Décision | Raison |
|---|---|
| **Tauri v2 + HTML/CSS/JS vanilla** | imposé ; zéro framework, bundle ~10 Mo vs Electron ~200 Mo |
| **Pas de crate WMI/machine-uid** | `reg query` + PowerShell suffisent ; empreinte = SHA-256 (crate `sha2`) |
| **reqwest + rustls** | webhook + whitelist sans OpenSSL |
| **CSPRNG** | crate `getrandom` (BCryptGenRandom) pour les sels du coffre réécrit — jamais d'entropie faite maison |
| **Tray + single-instance + window-state** | plugins officiels ; 2e lancement → focus ; fermer → tray (réglable) |
| **Updater signé** | `tauri-plugin-updater`, clés minisign générées (pubkey dans `tauri.conf.json`, privée **hors dépôt** : `%USERPROFILE%\.ravenne-keys\`) |
| **Presse-papiers** | `clipboard_copy_autoclear` efface après N secondes (réglable) |
| **frontendDist `../ui`** | pas de serveur de dev ; `esbuild` bundle `ui/src/*.js` → `ui/app.min.js` (`npm run ui:bundle`) |

## Motion — où trouver chaque règle

- Tokens et utilitaires : `ui/styles.css` (`--ease-out`, `--ease-inout`, `--dur-*`, `--stagger`,
  `--press`, `--stretch`, `--pop-in`) — commentaires `spec #n` sur chaque bloc.
- JS : `ui/src/motion.js` — `switchScreen` (#13), `stagger` (#3), `flipPersist` (#16+#6+#10),
  `openFromTrigger` (#10), `pulse` (#7), `swapStateIcon` (#15), `rubberBand` (#11),
  `reveal` (#14). Les règles #1/#2/#4/#5/#8/#12/#17 sont dans les CSS.
- `prefers-reduced-motion` + réglage « Animations » court-circuitent tout (#17).

## Lancer / builder

```
npm run ui:dev      → tauri dev (compile Rust au premier lancement, ~5-15 min)
npm run ui:build    → tauri build (NSIS + artefacts updater signés)
npm run ui:bundle   → esbuild uniquement (frontend)
```

Test navigateur sans Rust : ouvrir `ui/index.html` via un serveur statique —
le frontend détecte l'absence de Tauri et bascule sur un **mock complet** du bridge
(`ui/src/bridge.js`), y compris whitelist/flag/vault. Mot de passe mock : `Demo12345`.

## Release (auto-update)

1. `tauri.conf.json` → `plugins.updater.endpoints` : mettre ton `OWNER/REPO`.
2. Secrets GitHub : `TAURI_SIGNING_PRIVATE_KEY` (contenu de la clé privée) + `TAURI_SIGNING_KEY_PASSWORD`.
3. Pousser un tag `v*` → le workflow `.github/workflows/release.yml` build NSIS + `latest.json` signé.
4. L'app au démarrage (non bloquant) compare, télécharge, vérifie la signature, relance,
   puis affiche le changelog avec pulsation de réussite. Canal bêta = préreleases.

## Limites honnêtes

- Le verrou HWID **ne remplace pas** le mot de passe maître : il est contournable par
  quelqu'un qui maîtrise la machine ; la vraie sécurité reste le coffre chiffré.
- Envois EVM fonctionnels dans l'UI ; les envois BTC/XMR restent dans le CLI (moteurs
  spécialisés) — l'UI affiche leurs soldes et renvoie vers le CLI pour signer.
- Le thème « auto » suit Windows ; la traduction FR couvre les libellés principaux
  (réglage `language`, extension triviale via le dictionnaire).
