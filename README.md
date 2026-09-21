# CryptoShare — Échange chiffré de fichiers, images et textes

Application web de démonstration pour TP Cybersécurité : deux utilisateurs
s'échangent des messages (texte, fichier, image) chiffrés de bout en bout.

## 1. Installation et lancement

```bash
cd cryptoshare
npm install
npm start
```

Puis ouvrez `http://localhost:3000` dans **deux onglets (ou deux navigateurs)
différents** — un pour chaque utilisateur, par exemple `alice` et `bob`.

1. Onglet 1 : connectez-vous en tant que `alice`
2. Onglet 2 : connectez-vous en tant que `bob`
3. Dans l'onglet d'alice, choisissez `bob` comme destinataire, écrivez un
   texte ou joignez un fichier/image, cliquez sur "Chiffrer & envoyer"
4. Dans l'onglet de bob, le message apparaît chiffré dans la boîte de
   réception (vous voyez le ciphertext brut) ; cliquez sur "Déchiffrer"
   pour révéler le contenu

Pour tester la stéganographie, utilisez l'onglet `Stéganographie`, choisissez
le support porteur (`Image`, `Audio WAV` ou `Vidéo`), puis le texte/fichier à
cacher. Pour l'audio, utilisez un fichier `.wav` non compressé ; pour la vidéo,
préférez un petit fichier MP4/WebM afin de garder l'échange léger via Cloudflare.

## 2. Architecture et principe cryptographique

### Chiffrement hybride RSA + AES

Le chiffrement se fait **entièrement dans le navigateur**, via l'API native
`window.crypto.subtle` (Web Crypto API) — aucune librairie tierce, ce qui
est plus facilement défendable dans un rapport académique.

| Élément | Algorithme | Rôle |
|---|---|---|
| Clé de session | AES-256-GCM | Chiffre le contenu réel (texte/fichier/image), rapide, taille illimitée |
| Clé publique/privée | RSA-OAEP 2048 bits, SHA-256 | Chiffre uniquement la petite clé AES, pour la transmettre en toute confidentialité au bon destinataire |

**Pourquoi hybride et pas RSA seul ?** RSA ne peut chiffrer que de très
petites quantités de données (quelques centaines d'octets avec OAEP) et
est lent sur de gros volumes. On ne l'utilise donc que pour "envelopper"
la clé AES ; c'est exactement le principe utilisé par PGP/GPG et par la
poignée de main TLS.

### Déroulé d'un envoi (A → B)

1. A génère une clé AES-256 aléatoire, **unique pour ce message**
2. A chiffre le contenu avec AES-GCM (produit `ciphertext` + tag d'intégrité)
3. A chiffre la clé AES avec la **clé publique RSA de B** (`encryptedKey`)
4. A envoie au serveur : `{ciphertext, encryptedKey, iv}` — tout est illisible sans la clé privée de B

### Déroulé d'une réception (B)

1. B récupère le message chiffré depuis le serveur
2. B déchiffre `encryptedKey` avec **sa clé privée RSA** → récupère la clé AES
3. B déchiffre `ciphertext` avec cette clé AES → obtient le contenu en clair

### Pourquoi le serveur ne peut rien lire

La clé privée RSA de chaque utilisateur est générée dans le navigateur et
stockée uniquement dans le `localStorage` de ce navigateur — elle n'est
**jamais envoyée au serveur**. Le serveur ne stocke que :
- les clés **publiques** (normal, elles sont faites pour être publiques)
- des messages déjà chiffrés (blobs opaques)

Même un accès complet à la base de données du serveur (`data/*.json`) ne
permet pas de lire le contenu des messages. C'est le principe du
chiffrement de bout en bout (*end-to-end encryption*, comme Signal ou
WhatsApp).

### Intégrité des données

Le mode **AES-GCM** (Galois/Counter Mode) est un mode de chiffrement
authentifié : il produit, en plus du texte chiffré, un tag d'authentification.
Si un seul octet du message est modifié en transit (attaque active), le
déchiffrement échoue explicitement au lieu de renvoyer des données corrompues
silencieusement. Vous pouvez le démontrer pour votre rapport en modifiant
manuellement un caractère du champ `ciphertext` dans `data/messages.json`
pendant qu'un message est en attente, puis en essayant de le déchiffrer.

### Stéganographie image, audio et vidéo

La charge cachée est toujours un JSON contenant `{iv, encryptedKey,
ciphertext}` : elle est donc chiffrée avant d'être dissimulée.

- **Image** : insertion LSB dans les canaux RGB, puis export en PNG sans perte.
- **Audio WAV** : insertion LSB dans les octets PCM du chunk `data`.
- **Vidéo** : ajout de la charge chiffrée en fin de conteneur vidéo, sans
  réencodage des images. Cette méthode est robuste pour la démo, mais plus
  facile à détecter par analyse binaire qu'une vraie dissimulation dans les
  frames.

### Limite volontairement non traitée : l'authenticité des clés publiques

Ce schéma protège la **confidentialité** (personne d'autre que le
destinataire ne peut lire) et l'**intégrité** (toute altération est
détectée), mais pas nativement l'authenticité de la clé publique récupérée
(attaque de type "homme du milieu" si un serveur malveillant substituait
la clé publique de bob par la sienne). C'est pourquoi l'application affiche
une **empreinte de clé** (fingerprint, dérivée du modulus RSA en SHA-256) :
en pratique, ce problème se résout en vérifiant cette empreinte par un canal
indépendant (téléphone, rencontre physique, QR code) — exactement comme
PGP ou Signal. C'est un excellent axe à discuter dans la partie "limites"
de votre rapport.

## 3. Structure du projet

```
cryptoshare/
├── server.js              # Relais HTTP : stocke clés publiques + blobs chiffrés uniquement
├── data/                   # "Base de données" JSON (créée au premier lancement)
├── public/
│   ├── index.html
│   ├── style.css
│   └── js/
│       ├── crypto.js       # Tout le chiffrement/déchiffrement (Web Crypto API)
│       ├── audio-steganography.js
│       ├── media-container-steganography.js
│       └── app.js          # Logique d'interface (connexion, envoi, réception)
└── package.json
```

## 4. Pistes d'amélioration à mentionner dans le rapport

- Signature numérique (RSA-PSS) des messages pour garantir leur **authenticité**
  (prouver que c'est bien A qui a envoyé, pas seulement B qui peut lire)
- Vérification d'empreinte via QR code scanné en personne
- Rotation des clés / expiration
- Persistance en base de données réelle (SQLite/PostgreSQL) au lieu de JSON
- HTTPS obligatoire en production (ici, tout tourne en HTTP local pour le TP)
