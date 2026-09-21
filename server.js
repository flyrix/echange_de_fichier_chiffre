/**
 * CryptoShare - Serveur de relais
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, "[]");

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    return file === MESSAGES_FILE ? [] : {};
  }
}

// Écriture atomique sécurisée pour éviter la corruption de fichier
function writeJSON(file, data) {
  const tmpFile = `${file}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
  fs.renameSync(tmpFile, file);
}

app.post("/api/register", (req, res) => {
  const { username, publicKeyJwk } = req.body;
  if (!username || !publicKeyJwk) {
    return res.status(400).json({ error: "username et publicKeyJwk requis" });
  }
  const users = readJSON(USERS_FILE);
  users[username] = {
    publicKeyJwk,
    fingerprint: fingerprintOf(publicKeyJwk),
    registeredAt: Date.now(),
  };
  writeJSON(USERS_FILE, users);
  res.json({ ok: true, fingerprint: users[username].fingerprint });
});

app.get("/api/users", (req, res) => {
  const users = readJSON(USERS_FILE);
  const list = Object.keys(users).map((username) => ({
    username,
    fingerprint: users[username].fingerprint,
  }));
  res.json(list);
});

app.get("/api/publickey/:username", (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users[req.params.username];
  if (!user) return res.status(404).json({ error: "utilisateur inconnu" });
  res.json({ publicKeyJwk: user.publicKeyJwk, fingerprint: user.fingerprint });
});

app.post("/api/send", (req, res) => {
  const {
    from,
    to,
    type,
    filename,
    mimeType,
    iv,
    encryptedKey,
    ciphertext,
    imageData,
    stegoKind,
    carrierData,
    carrierMimeType,
    carrierFilename,
  } = req.body;

  if (!from || !to) {
    return res.status(400).json({ error: "champs manquants" });
  }

  const isStego = type === "stego";
  const normalizedStegoKind = stegoKind || (imageData ? "image" : null);
  const normalizedCarrierData = carrierData || imageData;
  const normalizedCarrierMimeType =
    carrierMimeType || (normalizedStegoKind === "image" ? "image/png" : "application/octet-stream");

  if (isStego && !normalizedCarrierData) {
    return res.status(400).json({ error: "support porteur manquant pour un message stego" });
  }
  if (isStego && !["image", "audio", "video"].includes(normalizedStegoKind)) {
    return res.status(400).json({ error: "type de steganographie inconnu" });
  }
  if (!isStego && (!iv || !encryptedKey || !ciphertext)) {
    return res.status(400).json({ error: "champs manquants" });
  }

  const messages = readJSON(MESSAGES_FILE);
  
  // Construction du message nettoyé (suppression du doublon imageData)
  const message = {
    id: crypto.randomUUID(),
    from,
    to,
    type: type || "file",
    filename: isStego ? null : filename || null,
    mimeType: isStego ? normalizedCarrierMimeType : mimeType || "application/octet-stream",
    stegoKind: isStego ? normalizedStegoKind : null,
    carrierFilename: isStego ? carrierFilename || null : null,
    carrierMimeType: isStego ? normalizedCarrierMimeType : null,
    carrierData: isStego ? normalizedCarrierData : null,
    iv: isStego ? null : iv,
    encryptedKey: isStego ? null : encryptedKey,
    ciphertext: isStego ? null : ciphertext,
    sentAt: Date.now(),
    read: false,
  };

  messages.push(message);
  writeJSON(MESSAGES_FILE, messages);
  res.json({ ok: true, id: message.id });
});

app.get("/api/inbox/:username", (req, res) => {
  const messages = readJSON(MESSAGES_FILE);
  const inbox = messages.filter((m) => m.to === req.params.username);
  res.json(inbox);
});

app.get("/api/conversation/:username/:peer", (req, res) => {
  const { username, peer } = req.params;
  const messages = readJSON(MESSAGES_FILE);
  const conversation = messages.filter(
    (m) => (m.from === username && m.to === peer) || (m.from === peer && m.to === username)
  );
  res.json(conversation);
});

app.post("/api/mark-read/:id", (req, res) => {
  const messages = readJSON(MESSAGES_FILE);
  const msg = messages.find((m) => m.id === req.params.id);
  if (msg) {
    msg.read = true;
    writeJSON(MESSAGES_FILE, messages);
  }
  res.json({ ok: true });
});

function fingerprintOf(jwk) {
  const hash = crypto.createHash("sha256").update(jwk.n || "").digest("hex");
  return hash.match(/.{1,4}/g).slice(0, 8).join(" ");
}

app.listen(PORT, () => {
  console.log(`CryptoShare lance sur http://localhost:${PORT}`);
});