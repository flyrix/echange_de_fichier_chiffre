/**
 * Logique applicative CryptoShare. Gère :
 *  - la "connexion" (génération ou reprise d'une paire de clés RSA locale)
 *  - la liste des correspondants
 *  - l'envoi (chiffrement) et la réception (déchiffrement) des messages
 *
 * IMPORTANT : la clé privée est stockée uniquement dans le localStorage
 * DU NAVIGATEUR de l'utilisateur (sous privatekey_<username>), jamais
 * envoyée au serveur. C'est cette séparation qui rend l'échange chiffré
 * de bout en bout : le serveur ne manipule que des blobs opaques.
 */

let currentUser = null;
let myPrivateKeyJwk = null;
let myPublicKeyJwk = null;
let usersCache = [];
let inboxRefreshTimer = null;
let usersRefreshTimer = null;

const $ = (sel) => document.querySelector(sel);
const MAX_STEGO_CARRIER_BYTES = 55 * 1024 * 1024;
const STEGO_KIND_LABELS = {
  image: "image stégo",
  audio: "audio stégo",
  video: "vidéo stégo",
};

function getSteganography() {
  if (!window.Steganography) {
    throw new Error("module de stéganographie non chargé : rechargez la page avec Ctrl+F5");
  }
  return window.Steganography;
}

function getAudioSteganography() {
  if (!window.AudioSteganography) {
    throw new Error("module de stéganographie audio non chargé : rechargez la page avec Ctrl+F5");
  }
  return window.AudioSteganography;
}

function getMediaContainerSteganography() {
  if (!window.MediaContainerSteganography) {
    throw new Error("module de stéganographie vidéo non chargé : rechargez la page avec Ctrl+F5");
  }
  return window.MediaContainerSteganography;
}

function getSteganalysis() {
  if (!window.Steganalysis) {
    throw new Error("module de stéganalyse non chargé : rechargez la page avec Ctrl+F5");
  }
  return window.Steganalysis;
}

// ---------------------------------------------------------------------
// Connexion / génération de clés
// ---------------------------------------------------------------------

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("#username-input").value.trim();
  if (!username) return;

  setStatus("#login-status", "Génération de la paire de clés RSA-2048...", "");

  try {
    const storedPriv = localStorage.getItem(`privatekey_${username}`);
    const storedPub = localStorage.getItem(`publickey_${username}`);

    if (storedPriv && storedPub) {
      // Clés déjà générées lors d'une session précédente sur ce navigateur
      myPrivateKeyJwk = JSON.parse(storedPriv);
      myPublicKeyJwk = JSON.parse(storedPub);
      setStatus("#login-status", "Clés existantes retrouvées localement.", "ok");
    } else {
      const { publicKeyJwk, privateKeyJwk } = await CryptoEngine.generateKeyPair();
      myPrivateKeyJwk = privateKeyJwk;
      myPublicKeyJwk = publicKeyJwk;
      localStorage.setItem(`privatekey_${username}`, JSON.stringify(privateKeyJwk));
      localStorage.setItem(`publickey_${username}`, JSON.stringify(publicKeyJwk));
    }

    // On enregistre (ou met à jour) la clé PUBLIQUE auprès du serveur
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, publicKeyJwk: myPublicKeyJwk }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "échec de l'enregistrement");

    currentUser = username;
    $("#my-fingerprint").textContent = data.fingerprint;
    $("#identity-name").textContent = username;
    $("#identity-fingerprint").textContent = data.fingerprint;
    $("#identity-chip").classList.remove("hidden");
    $("#toggle-steganalysis").classList.remove("hidden");
    $("#login-screen").classList.add("hidden");
    $("#app-screen").classList.remove("hidden");

    await refreshUsers();
    await refreshInbox();
    if (inboxRefreshTimer) clearInterval(inboxRefreshTimer);
    if (usersRefreshTimer) clearInterval(usersRefreshTimer);
    inboxRefreshTimer = setInterval(refreshInbox, 4000); // polling simple du dialogue
    usersRefreshTimer = setInterval(refreshUsers, 4000); // polling simple de la liste des correspondants
  } catch (err) {
    setStatus("#login-status", "Erreur : " + err.message, "err");
  }
});

// ---------------------------------------------------------------------
// Liste des correspondants
// ---------------------------------------------------------------------

async function refreshUsers() {
  const res = await fetch("/api/users");
  usersCache = await res.json();

  const list = $("#user-list");
  list.innerHTML = "";
  const select = $("#recipient-select");
  const previousValue = select.value;
  select.innerHTML = "";

  usersCache
    .filter((u) => u.username !== currentUser)
    .forEach((u) => {
      const li = document.createElement("li");
      li.innerHTML = `<span>${escapeHtml(u.username)}</span><span class="uf">${u.fingerprint}</span>`;
      list.appendChild(li);

      const opt = document.createElement("option");
      opt.value = u.username;
      opt.textContent = u.username;
      select.appendChild(opt);
    });

  if (!select.options.length) {
    const opt = document.createElement("option");
    opt.textContent = "Aucun autre utilisateur inscrit pour l'instant";
    opt.disabled = true;
    select.appendChild(opt);
  } else if ([...select.options].some((o) => o.value === previousValue)) {
    select.value = previousValue;
  }

  updateConversationTitle();
}

$("#recipient-select").addEventListener("change", refreshInbox);

// ---------------------------------------------------------------------
// Onglets Texte / Fichier / Stéganographie
// ---------------------------------------------------------------------

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.querySelectorAll("[data-tab-panel]").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.tabPanel !== tab);
    });
  });
});

// Sous-onglets de l'onglet Stéganographie (texte à cacher / fichier à cacher)
document.querySelectorAll(".subtab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".subtab-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const sub = btn.dataset.subtab;
    document.querySelectorAll("[data-subtab-panel]").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.subtabPanel !== sub);
    });
    updateStegoCapacityHint();
  });
});

// Support porteur de l'onglet stéganographie (image / audio / vidéo)
document.querySelectorAll(".carrier-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".carrier-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const carrier = btn.dataset.carrier;
    document.querySelectorAll("[data-carrier-panel]").forEach((p) => {
      p.classList.toggle("hidden", p.dataset.carrierPanel !== carrier);
    });
    updateStegoCapacityHint();
  });
});

// Estimation de capacité en temps réel
$("#cover-image-input").addEventListener("change", updateStegoCapacityHint);
$("#cover-audio-input").addEventListener("change", updateStegoCapacityHint);
$("#cover-video-input").addEventListener("change", updateStegoCapacityHint);
$("#stego-text-input").addEventListener("input", updateStegoCapacityHint);
$("#stego-file-input").addEventListener("change", updateStegoCapacityHint);

async function updateStegoCapacityHint() {
  const hint = $("#stego-capacity");
  const carrier = selectedStegoCarrier();
  const coverFile = selectedCarrierFile(carrier);
  if (!coverFile) {
    hint.textContent = "";
    return;
  }
  try {
    const estimatedNeeded = estimateStegoPayloadBytes();
    await renderCarrierCapacityHint(hint, carrier, coverFile, estimatedNeeded);
  } catch (err) {
    hint.textContent = err.message;
    hint.className = "mini-note warn";
  }
}

function selectedStegoCarrier() {
  const active = document.querySelector(".carrier-btn.active");
  return active ? active.dataset.carrier : "image";
}

function selectedCarrierFile(carrier) {
  if (carrier === "audio") return $("#cover-audio-input").files[0];
  if (carrier === "video") return $("#cover-video-input").files[0];
  return $("#cover-image-input").files[0];
}

function estimateStegoPayloadBytes() {
  const activeSub = document.querySelector(".subtab-btn.active").dataset.subtab;
  let neededPlainBytes = 0;
  if (activeSub === "stego-text") {
    neededPlainBytes = new TextEncoder().encode($("#stego-text-input").value).length;
  } else {
    const f = $("#stego-file-input").files[0];
    neededPlainBytes = f ? f.size : 0;
  }

  // Surcharge large : AES-GCM, clé RSA chiffrée, JSON et base64.
  return Math.ceil(neededPlainBytes * 1.4) + 500;
}

async function renderCarrierCapacityHint(hint, carrier, coverFile, estimatedNeeded) {
  if (carrier === "image") {
    const img = await loadImageFromFile(coverFile);
    const { imageData } = drawToCanvas(img);
    const capacity = getSteganography().capacityBytes(imageData);
    renderCapacityComparison(hint, "Capacité de l'image", capacity, estimatedNeeded);
    return;
  }

  if (carrier === "audio") {
    const buffer = await coverFile.arrayBuffer();
    const capacity = getAudioSteganography().capacityBytes(buffer);
    renderCapacityComparison(hint, "Capacité du WAV", capacity, estimatedNeeded);
    return;
  }

  const estimatedOutput = coverFile.size + estimatedNeeded + 8;
  if (estimatedOutput > MAX_STEGO_CARRIER_BYTES) {
    hint.textContent = `Vidéo trop lourde pour la démo : sortie estimée ${(estimatedOutput / 1024 / 1024).toFixed(1)} Mo. Choisissez un extrait plus court.`;
    hint.className = "mini-note warn";
  } else {
    hint.textContent = `Vidéo prête : sortie estimée ${(estimatedOutput / 1024 / 1024).toFixed(1)} Mo.`;
    hint.className = "mini-note ok";
  }
}

function renderCapacityComparison(hint, label, capacity, estimatedNeeded) {
  if (estimatedNeeded > capacity) {
    hint.textContent = `${label} : ~${(capacity / 1024).toFixed(1)} Ko — insuffisant pour ce contenu (besoin estimé ~${(estimatedNeeded / 1024).toFixed(1)} Ko).`;
    hint.className = "mini-note warn";
  } else {
    hint.textContent = `${label} : ~${(capacity / 1024).toFixed(1)} Ko — suffisant.`;
    hint.className = "mini-note ok";
  }
}

// ---------------------------------------------------------------------
// Utilitaires image / canvas (partagés stéganographie + stéganalyse)
// ---------------------------------------------------------------------

function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => loadImageFromDataUrl(reader.result).then(resolve, reject);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function loadImageFromDataUrl(dataUrl) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = dataUrl;
  });
}

/**
 * CORRECTION CLE : Désactivation du lissage d'image et passage du paramètre
 * willReadFrequently pour préserver les bits de poids faible (LSB).
 */
function drawToCanvas(img) {
  const canvas = document.createElement("canvas");
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(img, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return { canvas, ctx, imageData };
}

function bufferToDataUrl(buffer, mimeType) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(new Blob([buffer], { type: mimeType }));
  });
}

async function dataUrlToBuffer(dataUrl) {
  const res = await fetch(dataUrl);
  if (!res.ok) throw new Error("lecture du support porteur impossible");
  return res.arrayBuffer();
}

function getCarrierData(msg) {
  return msg.carrierData || msg.imageData;
}

function buildDownloadButton(dataUrl, filename, label) {
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  a.className = "download-stego-btn";
  a.textContent = label || "Télécharger le support stégo";
  return a;
}

function filenameWithSuffix(filename, suffix, fallbackExtension) {
  const safeName = filename || `support.${fallbackExtension}`;
  const dot = safeName.lastIndexOf(".");
  if (dot <= 0) return `${safeName}-${suffix}.${fallbackExtension}`;
  return `${safeName.slice(0, dot)}-${suffix}${safeName.slice(dot)}`;
}

// ---------------------------------------------------------------------
// Envoi (chiffrement, avec ou sans dissimulation stéganographique)
// ---------------------------------------------------------------------

$("#send-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const to = $("#recipient-select").value;
  const activeTab = document.querySelector(".tab-btn.active").dataset.tab;
  if (!to) return;

  setStatus("#send-status", "Chiffrement en cours...", "");

  try {
    const recipient = usersCache.find((u) => u.username === to);
    if (!recipient) throw new Error("destinataire introuvable");

    const pubRes = await fetch(`/api/publickey/${encodeURIComponent(to)}`);
    const { publicKeyJwk } = await pubRes.json();

    let body;

    if (activeTab === "stego") {
      body = await buildStegoPayload(publicKeyJwk);
    } else {
      let payload;
      if (activeTab === "text") {
        const text = $("#text-input").value;
        if (!text.trim()) throw new Error("le message texte est vide");
        const buffer = new TextEncoder().encode(text).buffer;
        const enc = await CryptoEngine.encryptForRecipient(buffer, publicKeyJwk);
        payload = { ...enc, type: "text", filename: null, mimeType: "text/plain" };
      } else {
        const file = $("#file-input").files[0];
        if (!file) throw new Error("aucun fichier sélectionné");
        const buffer = await file.arrayBuffer();
        const enc = await CryptoEngine.encryptForRecipient(buffer, publicKeyJwk);
        const type = file.type.startsWith("image/") ? "image" : "file";
        payload = { ...enc, type, filename: file.name, mimeType: file.type || "application/octet-stream" };
      }
      body = payload;
    }

    const res = await fetch("/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ from: currentUser, to, ...body }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "échec de l'envoi");

    setStatus(
      "#send-status",
      activeTab === "stego"
        ? `${STEGO_KIND_LABELS[body.stegoKind] || "Support stégo"} envoyé à ${to}.`
        : `Message chiffré envoyé à ${to}.`,
      "ok"
    );

    const downloadArea = $("#send-download-area");
    if (activeTab === "stego" && body.carrierData) {
      downloadArea.innerHTML = "";
      downloadArea.classList.remove("hidden");
      downloadArea.appendChild(
        buildDownloadButton(
          body.carrierData,
          body.carrierFilename || `stego.${(body.carrierMimeType || "").split("/")[1] || "bin"}`,
          `Télécharger le support stégo envoyé à ${to}`
        )
      );
    } else {
      downloadArea.classList.add("hidden");
      downloadArea.innerHTML = "";
    }

    $("#send-form").reset();
    $("#recipient-select").value = to;
    $("#stego-capacity").textContent = "";
    await refreshInbox();
  } catch (err) {
    setStatus("#send-status", "Erreur : " + err.message, "err");
  }
});

async function buildStegoPayload(publicKeyJwk) {
  const carrier = selectedStegoCarrier();
  const coverFile = selectedCarrierFile(carrier);
  if (!coverFile) throw new Error(`choisissez un support ${carrier}`);

  const activeSub = document.querySelector(".subtab-btn.active").dataset.subtab;
  let innerBuffer, innerType, innerFilename, innerMime;

  if (activeSub === "stego-text") {
    const text = $("#stego-text-input").value;
    if (!text.trim()) throw new Error("le message à cacher est vide");
    innerBuffer = new TextEncoder().encode(text).buffer;
    innerType = "text";
    innerFilename = null;
    innerMime = "text/plain";
  } else {
    const file = $("#stego-file-input").files[0];
    if (!file) throw new Error("choisissez un fichier à cacher");
    innerBuffer = await file.arrayBuffer();
    innerType = file.type.startsWith("image/") ? "image" : "file";
    innerFilename = file.name;
    innerMime = file.type || "application/octet-stream";
  }

  const stegoKey = getStegoKeyOrPrompt();
  if (!stegoKey) throw new Error("renseignez la clé de dissimulation partagée");

  const enc = await CryptoEngine.encryptForRecipient(innerBuffer, publicKeyJwk);
  const innerPayload = { ...enc, type: innerType, filename: innerFilename, mimeType: innerMime };
  const innerPayloadBytes = new TextEncoder().encode(JSON.stringify(innerPayload));

  if (carrier === "audio") {
    return buildAudioStegoPayload(coverFile, innerPayloadBytes, stegoKey);
  }
  if (carrier === "video") {
    return buildVideoStegoPayload(coverFile, innerPayloadBytes, stegoKey);
  }
  return buildImageStegoPayload(coverFile, innerPayloadBytes, stegoKey);
}

async function buildImageStegoPayload(coverFile, innerPayloadBytes, stegoKey) {
  const coverImg = await loadImageFromFile(coverFile);
  const { canvas, ctx, imageData } = drawToCanvas(coverImg);

  const steganography = getSteganography();
  const capacity = steganography.capacityBytes(imageData);
  if (innerPayloadBytes.length > capacity) {
    throw new Error(
      `image de couverture trop petite (capacité ${(capacity / 1024).toFixed(1)} Ko, besoin ${(innerPayloadBytes.length / 1024).toFixed(1)} Ko) — choisissez une image plus grande`
    );
  }

  steganography.embed(imageData, innerPayloadBytes, stegoKey);
  ctx.putImageData(imageData, 0, 0);
  const stegoDataUrl = canvas.toDataURL("image/png");

  return {
    type: "stego",
    stegoKind: "image",
    carrierData: stegoDataUrl,
    carrierMimeType: "image/png",
    carrierFilename: filenameWithSuffix(coverFile.name, "cryptoshare", "png").replace(/\.[^.]+$/, ".png"),
    imageData: stegoDataUrl,
  };
}

async function buildAudioStegoPayload(coverFile, innerPayloadBytes) {
  const coverBuffer = await coverFile.arrayBuffer();
  const stegoBuffer = getAudioSteganography().embed(coverBuffer, innerPayloadBytes);
  const stegoDataUrl = await bufferToDataUrl(stegoBuffer, "audio/wav");

  return {
    type: "stego",
    stegoKind: "audio",
    carrierData: stegoDataUrl,
    carrierMimeType: "audio/wav",
    carrierFilename: filenameWithSuffix(coverFile.name, "cryptoshare", "wav").replace(/\.[^.]+$/, ".wav"),
  };
}

async function buildVideoStegoPayload(coverFile, innerPayloadBytes, stegoKey) {
  const coverBuffer = await coverFile.arrayBuffer();
  const outputBytes = coverFile.size + innerPayloadBytes.length + 12;
  if (outputBytes > MAX_STEGO_CARRIER_BYTES) {
    throw new Error(
      `vidéo trop lourde pour la démo (${(outputBytes / 1024 / 1024).toFixed(1)} Mo après dissimulation)`
    );
  }

  const stegoBuffer = getMediaContainerSteganography().embed(coverBuffer, innerPayloadBytes, stegoKey);
  const mimeType = coverFile.type || "video/mp4";
  const stegoDataUrl = await bufferToDataUrl(stegoBuffer, mimeType);

  return {
    type: "stego",
    stegoKind: "video",
    carrierData: stegoDataUrl,
    carrierMimeType: mimeType,
    carrierFilename: filenameWithSuffix(coverFile.name, "cryptoshare", mimeType.includes("webm") ? "webm" : "mp4"),
  };
}

// ---------------------------------------------------------------------
// Réception et déchiffrement
// ---------------------------------------------------------------------

async function refreshInbox() {
  if (!currentUser) return;
  const peer = selectedRecipient();
  updateConversationTitle();

  if (!peer) {
    $("#inbox-list").innerHTML = `<li class="empty-state">Aucun correspondant sélectionné.</li>`;
    return;
  }

  const res = await fetch(
    `/api/conversation/${encodeURIComponent(currentUser)}/${encodeURIComponent(peer)}`
  );
  const messages = await res.json();

  const list = $("#inbox-list");
  const alreadyOpen = new Set(
    [...list.querySelectorAll(".inbox-item[data-id]")]
      .filter((el) => !el.querySelector(".decrypted-content").classList.contains("hidden"))
      .map((el) => el.dataset.id)
  );

  if (!messages.length) {
    list.innerHTML = `<li class="empty-state">Aucun message avec ${escapeHtml(peer)} pour l'instant.</li>`;
    return;
  }

  list.innerHTML = "";
  messages
    .sort((a, b) => a.sentAt - b.sentAt)
    .forEach((msg) => {
      const template = $("#inbox-item-template").content.cloneNode(true);
      const li = template.querySelector(".inbox-item");
      const isOutgoing = msg.from === currentUser;
      li.dataset.id = msg.id;
      li.classList.add(isOutgoing ? "outgoing" : "incoming");
      li.querySelector(".from-label").textContent = `${
        isOutgoing ? "Vous" : msg.from
      } · ${messageTypeLabel(msg)}`;
      li.querySelector(".time-label").textContent = new Date(msg.sentAt).toLocaleTimeString();

      const previewBox = li.querySelector(".cipher-preview");
      const decryptBtn = li.querySelector(".decrypt-btn");
      const steganalyzeBtn = li.querySelector(".steganalyze-btn");
      const contentBox = li.querySelector(".decrypted-content");
      renderCipherPreview(previewBox, msg, isOutgoing);

      if (msg.type === "stego" && (msg.stegoKind || "image") === "image") {
        steganalyzeBtn.classList.remove("hidden");
      }

      if (isOutgoing) {
        decryptBtn.classList.add("hidden");
      }

      decryptBtn.addEventListener("click", async () => {
        await decryptAndRender(msg, contentBox);
      });
      steganalyzeBtn.addEventListener("click", async () => {
        $("#toggle-steganalysis").click();
        await runSteganalysisOnDataUrl(getCarrierData(msg));
      });

      list.appendChild(li);

      if (!isOutgoing && alreadyOpen.has(msg.id)) {
        decryptBtn.click();
      }
    });

  list.scrollTop = list.scrollHeight;
}

function selectedRecipient() {
  const select = $("#recipient-select");
  const selected = select.options[select.selectedIndex];
  if (!selected || selected.disabled || !select.value) return null;
  return select.value;
}

function updateConversationTitle() {
  const peer = selectedRecipient();
  $("#conversation-title").textContent = peer ? `Dialogue avec ${peer}` : "Dialogue chiffré";
}

function messageTypeLabel(msg) {
  if (msg.type === "stego") return STEGO_KIND_LABELS[msg.stegoKind || "image"] || "support stégo";
  if (msg.type === "text") return "texte chiffré";
  if (msg.type === "image") return `image chiffrée${msg.filename ? " · " + msg.filename : ""}`;
  return `fichier chiffré${msg.filename ? " · " + msg.filename : ""}`;
}

function renderCipherPreview(previewBox, msg, isOutgoing) {
  previewBox.innerHTML = "";
  previewBox.style.padding = "";
  previewBox.style.background = "";

  if (msg.type === "stego") {
    const stegoKind = msg.stegoKind || "image";
    const carrierData = getCarrierData(msg);
    previewBox.classList.add("cipher-preview-stego");
    const media = document.createElement(stegoKind === "audio" ? "audio" : stegoKind === "video" ? "video" : "img");
    media.className = `stego-thumb stego-${stegoKind}`;
    media.src = carrierData;
    if (stegoKind !== "image") {
      media.controls = true;
      media.preload = "metadata";
    }
    const caption = document.createElement("div");
    caption.className = "stego-caption";
    caption.textContent = isOutgoing
      ? `${STEGO_KIND_LABELS[stegoKind] || "Support stégo"} envoyé avec charge chiffrée dissimulée.`
      : `${STEGO_KIND_LABELS[stegoKind] || "Support stégo"} reçu avec charge chiffrée dissimulée.`;
    previewBox.appendChild(media);
    previewBox.appendChild(caption);
    previewBox.appendChild(
      buildDownloadButton(
        carrierData,
        msg.carrierFilename || `stego-${msg.id || "fichier"}.${stegoKind === "image" ? "png" : stegoKind === "audio" ? "wav" : "mp4"}`,
        "Télécharger ce support stégo"
      )
    );
    return;
  }

  previewBox.classList.remove("cipher-preview-stego");
  const cipherText = document.createElement("div");
  cipherText.className = "cipher-text";
  cipherText.textContent = msg.ciphertext;
  previewBox.appendChild(cipherText);

  const meta = document.createElement("div");
  meta.className = "cipher-meta";
  meta.textContent = `${isOutgoing ? "Envoyé" : "Reçu"} · ${msg.ciphertext.length} caractères chiffrés`;
  previewBox.appendChild(meta);
}

/**
 * CORRECTION CLE : Gestion d'erreurs segmentée pour différencier l'échec d'extraction LSB
 * de l'échec de déchiffrement cryptographique RSA/AES.
 */
async function decryptAndRender(msg, contentBox) {
  contentBox.classList.remove("hidden", "err");
  contentBox.textContent = msg.type === "stego" ? "Extraction LSB puis déchiffrement..." : "Déchiffrement...";

  try {
    let cryptoPayload = msg;
    let renderType = msg.type;
    let renderFilename = msg.filename;
    let renderMime = msg.mimeType;

    if (msg.type === "stego") {
      try {
        const hiddenJson = await extractStegoPayloadFromMessage(msg);
        cryptoPayload = hiddenJson;
        renderType = hiddenJson.type;
        renderFilename = hiddenJson.filename;
        renderMime = hiddenJson.mimeType;
      } catch (stegoErr) {
        throw new Error(`[Erreur Extraction Stégo] ${stegoErr.message}`);
      }
    }

    try {
      const plainBuffer = await CryptoEngine.decryptMessage(cryptoPayload, myPrivateKeyJwk);
      renderDecryptedPayload(contentBox, plainBuffer, renderType, renderFilename, renderMime);
      fetch(`/api/mark-read/${msg.id}`, { method: "POST" }).catch(() => {});
    } catch (cryptoErr) {
      throw new Error(`[Erreur Déchiffrement RSA/AES] La clé privée locale ne permet pas de déchiffrer ce message (${cryptoErr.message})`);
    }

  } catch (err) {
    contentBox.classList.add("err");
    contentBox.textContent = "Échec du traitement : " + err.message;
  }
}

async function extractStegoPayloadFromMessage(msg) {
  const stegoKind = msg.stegoKind || "image";
  const carrierData = getCarrierData(msg);
  if (!carrierData) throw new Error("support porteur absent");

  const stegoKey = getStegoKeyOrPrompt();
  if (!stegoKey) {
    throw new Error("clé de dissimulation partagée requise pour extraire ce support");
  }

  if (stegoKind === "image") {
    const img = await loadImageFromDataUrl(carrierData);
    const { imageData } = drawToCanvas(img);
    return extractStegoPayload(imageData, stegoKey);
  }

  if (stegoKind === "audio") {
    const buffer = await dataUrlToBuffer(carrierData);
    return decodeHiddenPayload(getAudioSteganography().extract(buffer, stegoKey));
  }

  if (stegoKind === "video") {
    const buffer = await dataUrlToBuffer(carrierData);
    return decodeHiddenPayload(getMediaContainerSteganography().extract(buffer, stegoKey));
  }

  throw new Error("type de support stéganographique inconnu");
}

// Le champ "Clé de dissimulation partagée" vit dans l'onglet Envoyer : un
// destinataire qui ouvre directement sa boîte de réception sans être passé
// par cet onglet le trouve vide. Plutôt que d'échouer, on la lui demande
// une fois (invite navigateur), on la reporte dans le champ pour les
// prochains envois/extractions de la session, et on ne redemande plus.
function getStegoKeyOrPrompt() {
  const input = $("#stego-shared-key");
  let value = (input.value || "").trim();
  if (!value) {
    const entered = window.prompt(
      "Clé de dissimulation partagée (convenue avec votre correspondant, hors de ce canal) :"
    );
    value = (entered || "").trim();
    if (value) input.value = value;
  }
  return value;
}

function extractStegoPayload(imageData, stegoKey) {
  return decodeHiddenPayload(getSteganography().extract(imageData, stegoKey));
}

function decodeHiddenPayload(hiddenBytes) {
  return JSON.parse(new TextDecoder().decode(hiddenBytes));
}

function renderDecryptedPayload(container, plainBuffer, renderType, renderFilename, renderMime) {
  if (renderType === "text") {
    const text = new TextDecoder().decode(plainBuffer);
    container.innerHTML = `<div class="plain-text"></div>`;
    container.querySelector(".plain-text").textContent = text;
    return;
  }

  const filename = renderFilename || "fichier_dechiffre";
  const mimeType = renderMime || "application/octet-stream";
  const blob = new Blob([plainBuffer], { type: mimeType });
  const url = URL.createObjectURL(blob);
  if (renderType === "image") {
    container.innerHTML = "";
    const img = document.createElement("img");
    img.src = url;
    img.alt = filename;
    container.appendChild(img);
    container.appendChild(buildFileActions(url, filename));
    return;
  }

  renderDocumentPayload(container, plainBuffer, url, filename, mimeType);
}

function renderDocumentPayload(container, plainBuffer, url, filename, mimeType) {
  container.innerHTML = "";

  const panel = document.createElement("div");
  panel.className = "file-preview-panel";

  const meta = document.createElement("div");
  meta.className = "file-preview-meta";
  meta.textContent = `${filename} · ${mimeType}`;
  panel.appendChild(meta);

  const previewKind = getInlinePreviewKind(filename, mimeType);
  const actions = buildFileActions(url, filename);
  if (previewKind) {
    const openInlineBtn = document.createElement("button");
    openInlineBtn.type = "button";
    openInlineBtn.className = "file-action-btn";
    openInlineBtn.textContent = "Ouvrir ici";
    actions.prepend(openInlineBtn);

    const preview = document.createElement("div");
    preview.className = "inline-file-preview hidden";
    panel.appendChild(actions);
    panel.appendChild(preview);

    openInlineBtn.addEventListener("click", () => {
      renderInlinePreview(preview, plainBuffer, url, filename, previewKind);
      preview.classList.remove("hidden");
    });
  } else {
    const note = document.createElement("p");
    note.className = "file-preview-note";
    note.textContent =
      "Aperçu direct indisponible pour ce format dans le navigateur. Utilisez l'ouverture dans un nouvel onglet ou le téléchargement.";
    panel.appendChild(actions);
    panel.appendChild(note);
  }

  container.appendChild(panel);
}

function buildFileActions(url, filename) {
  const actions = document.createElement("div");
  actions.className = "file-actions";

  const openLink = document.createElement("a");
  openLink.className = "file-link";
  openLink.href = url;
  openLink.target = "_blank";
  openLink.rel = "noopener";
  openLink.textContent = "Nouvel onglet";
  actions.appendChild(openLink);

  const downloadLink = document.createElement("a");
  downloadLink.className = "file-link";
  downloadLink.href = url;
  downloadLink.download = filename;
  downloadLink.textContent = "Télécharger";
  actions.appendChild(downloadLink);

  return actions;
}

function getInlinePreviewKind(filename, mimeType) {
  const name = (filename || "").toLowerCase();
  const mime = (mimeType || "").toLowerCase();
  if (mime === "application/pdf" || name.endsWith(".pdf")) return "pdf";
  if (
    mime.startsWith("text/") ||
    ["application/json", "application/xml", "application/javascript"].includes(mime) ||
    [".txt", ".csv", ".json", ".md", ".xml", ".js", ".css", ".html"].some((ext) => name.endsWith(ext))
  ) {
    return "text";
  }
  return null;
}

function renderInlinePreview(preview, plainBuffer, url, filename, previewKind) {
  preview.innerHTML = "";

  if (previewKind === "pdf") {
    const frame = document.createElement("iframe");
    frame.src = url;
    frame.title = filename;
    preview.appendChild(frame);
    return;
  }

  const textPreview = document.createElement("pre");
  textPreview.textContent = new TextDecoder().decode(plainBuffer);
  preview.appendChild(textPreview);
}

// ---------------------------------------------------------------------
// Utilitaires de statut & échappement
// ---------------------------------------------------------------------

function setStatus(selector, message, kind) {
  const el = $(selector);
  el.textContent = message;
  el.className = "status-line" + (kind ? " " + kind : "");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---------------------------------------------------------------------
// Boîte à outils de stéganalyse (Section complétée)
// ---------------------------------------------------------------------

$("#toggle-steganalysis").addEventListener("click", () => {
  const stegScreen = $("#steganalysis-screen");
  const isHidden = stegScreen.classList.contains("hidden");
  stegScreen.classList.toggle("hidden", !isHidden);
  $("#app-screen").classList.toggle("hidden", isHidden);
  $("#toggle-steganalysis").textContent = isHidden
    ? "Retour à la messagerie"
    : "Boîte à outils de stéganalyse";
});

let lastSteganalysisFile = null;

$("#steg-analyze-input").addEventListener("change", async () => {
  const file = $("#steg-analyze-input").files[0];
  if (!file) return;
  lastSteganalysisFile = file;
  $("#steg-extraction-output").className = "steg-extraction-output";
  $("#steg-extraction-output").textContent = "";
  await runSteganalysisOnFile(file);
});

$("#steg-try-extract-btn").addEventListener("click", async () => {
  if (!lastSteganalysisFile) return;
  await tryExtractWithKey(lastSteganalysisFile, ($("#steg-try-key").value || "").trim());
});

function sniffFileKind(bytes) {
  if (bytes.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((b, i) => bytes[i] === b)) {
    return "png";
  }
  if (bytes.length >= 12 && String.fromCharCode(...bytes.subarray(0, 4)) === "RIFF" && String.fromCharCode(...bytes.subarray(8, 12)) === "WAVE") {
    return "wav";
  }
  if (bytes.length >= 8 && String.fromCharCode(...bytes.subarray(4, 8)) === "ftyp") {
    return "mp4";
  }
  return "unknown";
}

async function runSteganalysisOnFile(file) {
  $("#steg-results").classList.remove("hidden");
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const kind = sniffFileKind(bytes);
  const steganalysis = getSteganalysis();
  const imageOnlyPanel = $("#steg-image-only");
  const report = $("#steg-report");

  if (kind === "png") {
    imageOnlyPanel.classList.remove("hidden");
    const img = await loadImageFromDataUrl(await fileToDataUrl(file));
    const { imageData } = drawToCanvas(img);

    const originalCanvas = $("#steg-original-canvas");
    originalCanvas.width = imageData.width;
    originalCanvas.height = imageData.height;
    originalCanvas.getContext("2d").putImageData(imageData, 0, 0);

    const result = steganalysis.analyzeImage(imageData);
    const trailer = steganalysis.analyzePngTrailer(bytes);

    // Affiche le canal le plus suspect (ou le bleu par défaut)
    const channelIdx = { R: 0, G: 1, B: 2 };
    const focus = result.perChannel.find((c) => c.suspicious) || result.perChannel[2];
    $("#steg-bitplane-label").textContent = focus.channel;
    $("#steg-chi-label").textContent = focus.channel;
    const bitPlaneData = steganalysis.extractBitPlane(imageData, channelIdx[focus.channel]);
    const bpCanvas = $("#steg-bitplane-canvas");
    bpCanvas.width = imageData.width;
    bpCanvas.height = imageData.height;
    bpCanvas.getContext("2d").putImageData(bitPlaneData, 0, 0);
    renderChiSquareChart($("#steg-chi-canvas"), focus.chiSquareCurve);

    report.innerHTML = renderImageReport(result, trailer);
  } else if (kind === "wav") {
    imageOnlyPanel.classList.add("hidden");
    const result = steganalysis.analyzeWav(bytes);
    report.innerHTML = renderWavReport(result);
  } else if (kind === "mp4") {
    imageOnlyPanel.classList.add("hidden");
    const result = steganalysis.analyzeMp4(bytes);
    report.innerHTML = renderMp4Report(result);
  } else {
    imageOnlyPanel.classList.add("hidden");
    const result = steganalysis.analyzeGenericFile(bytes);
    report.innerHTML = renderGenericReport(result);
  }
}

function verdictBadge(suspicious) {
  return suspicious
    ? `<span class="verdict-badge warn">⚠ Anomalie détectée</span>`
    : `<span class="verdict-badge ok">✓ Rien de statistiquement anormal détecté</span>`;
}

function renderImageReport(result, trailer) {
  const rows = result.perChannel
    .map(
      (c) => `<tr>
        <td>${c.channel}</td>
        <td>${c.chiSquareFinalPValue.toFixed(4)}</td>
        <td>${c.chiSquarePlateauDetected ? "oui" : "non"}</td>
        <td>${c.lsbRatio.toFixed(4)}</td>
        <td>${c.runsTest.notApplicable ? "n/a" : c.runsTest.z === null ? "n/a" : c.runsTest.z.toFixed(2)}</td>
        <td>${c.suspicious ? "⚠ suspect" : "ok"}</td>
      </tr>`
    )
    .join("");

  const trailerLine = trailer
    ? trailer.suspicious
      ? `<p class="warn-line">⚠ ${trailer.trailingBytes} octet(s) présents après le chunk IEND (fin logique du PNG) — signature typique d'un ajout brut de données.</p>`
      : `<p>Aucun octet superflu après IEND.</p>`
    : "";

  return `
    ${verdictBadge(result.overallSuspicious)}
    <table class="steg-table">
      <thead><tr><th>Canal</th><th>χ² p (final)</th><th>Plateau χ²</th><th>Ratio LSB</th><th>Runs z</th><th>Statut</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${trailerLine}
    <p class="hint">Seuils indicatifs : plateau χ² soutenu, ratio LSB à plus de 2 points de 0,5, ou |z| du test des séries &gt; 2,58 (confiance 99&nbsp;%).</p>
  `;
}

function renderWavReport(result) {
  if (!result.valid) return `<p class="warn-line">${escapeHtml(result.message)}</p>`;
  return `
    ${verdictBadge(result.suspicious)}
    <ul class="steg-list">
      <li>χ² p (final) : ${result.chiSquareFinalPValue.toFixed(4)} ${result.chiSquarePlateauDetected ? "— plateau soutenu détecté" : ""}</li>
      <li>Ratio de LSB à 1 : ${result.lsbRatio.toFixed(4)}</li>
      <li>Test des séries (z) : ${result.runsTest.z === null ? "n/a" : result.runsTest.z.toFixed(2)}</li>
      <li>Taille RIFF déclarée vs réelle : ${result.sizeMismatch ? "⚠ incohérente" : "cohérente"}</li>
      <li>Octets après le chunk 'data' : ${result.trailingBytes} ${result.trailingBytes > 0 ? "⚠ signature typique d'un ajout brut" : ""}</li>
    </ul>
  `;
}

function renderMp4Report(result) {
  if (!result.valid) return `<p class="warn-line">${escapeHtml(result.message)}</p>`;
  const rows = result.boxes
    .map(
      (b) => `<tr class="${b.suspicious ? "row-warn" : ""}">
        <td>${escapeHtml(b.type)}</td><td>${b.size}</td><td>${b.entropy}/8</td>
        <td>${b.known ? "connue" : "⚠ inconnue"}</td><td>${b.suspicious ? "⚠" : "ok"}</td>
      </tr>`
    )
    .join("");
  return `
    ${verdictBadge(result.suspicious)}
    <table class="steg-table">
      <thead><tr><th>Box</th><th>Taille</th><th>Entropie</th><th>Type</th><th>Statut</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p>Octets superflus après la dernière box reconnue : ${result.trailingBytes} ${result.trailingBytes > 0 ? "⚠" : ""}</p>
    <p class="hint">Une box de type inconnu à forte entropie (proche de 8 bits/octet) est le signe le plus probant d'une charge chiffrée dissimulée dans le conteneur.</p>
  `;
}

function renderGenericReport(result) {
  if (result.type === "png-generic" || result.type === "wav" || result.type === "mp4") {
    // format reconnu via analyzeGenericFile mais routé ici par erreur : réutiliser les rendus dédiés
    if (result.type === "wav") return renderWavReport(result);
    if (result.type === "mp4") return renderMp4Report(result);
  }
  return `
    ${verdictBadge(result.suspicious)}
    <ul class="steg-list">
      <li>Entropie globale : ${result.globalEntropy.toFixed(3)} / 8 bits</li>
      ${result.trailer ? `<li>Octets après IEND (PNG) : ${result.trailer.trailingBytes}</li>` : ""}
      <li>${escapeHtml(result.message || "")}</li>
    </ul>
    <p class="hint">Une entropie proche de 8 sur l'ensemble du fichier est normale pour un format déjà compressé (JPEG, MP3, ZIP...) et n'indique pas forcément une dissimulation.</p>
  `;
}

async function tryExtractWithKey(file, key) {
  const output = $("#steg-extraction-output");
  output.className = "steg-extraction-output";
  if (!key) {
    output.textContent = "Renseignez une clé candidate pour tenter une extraction.";
    return;
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const kind = sniffFileKind(bytes);

  try {
    let payloadBytes;
    if (kind === "png") {
      const img = await loadImageFromDataUrl(await fileToDataUrl(file));
      const { imageData } = drawToCanvas(img);
      payloadBytes = getSteganography().extract(imageData, key);
    } else if (kind === "wav") {
      payloadBytes = getAudioSteganography().extract(bytes.buffer, key);
    } else if (kind === "mp4") {
      payloadBytes = getMediaContainerSteganography().extract(bytes.buffer, key);
    } else {
      throw new Error("format non pris en charge pour l'extraction (PNG, WAV ou MP4 uniquement)");
    }

    const decoded = decodeHiddenPayload(payloadBytes);
    output.textContent = `Succès : ${payloadBytes.length} octets extraits et déchiffrables en JSON — la clé fonctionne sur ce fichier (type dissimulé : ${decoded.type || "inconnu"}).`;
    output.classList.add("ok");
  } catch (err) {
    output.textContent = `Échec de l'extraction avec cette clé : ${err.message}`;
    output.classList.add("warn");
  }
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function renderChiSquareChart(canvas, results) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  // Arrière-plan du graphique
  ctx.fillStyle = "#1e1e1e";
  ctx.fillRect(0, 0, w, h);

  // Axes
  ctx.strokeStyle = "#444";
  ctx.beginPath();
  ctx.moveTo(30, 10);
  ctx.lineTo(30, h - 20);
  ctx.lineTo(w - 10, h - 20);
  ctx.stroke();

  if (!results || !results.length) return;

  // Tracé de la courbe P-Value
  ctx.strokeStyle = "#00ffcc";
  ctx.lineWidth = 2;
  ctx.beginPath();

  results.forEach((pt, i) => {
    const x = 30 + (pt.percent / 100) * (w - 40);
    const y = (h - 20) - pt.pValue * (h - 30);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}