window.Steganography = (() => {
  const HEADER_BITS = 32; // longueur du payload, encodée dans le flux permuté lui-même
  const PAD_BLOCK = 4096; // le budget de dissimulation est toujours arrondi à ce multiple

  // ---------------------------------------------------------------------
  // Dérivation de la graine à partir de la clé de dissimulation partagée
  // ---------------------------------------------------------------------
  // Hash synchrone (FNV-1a 32 bits + tours croisés) : suffisant ici car son
  // seul rôle est de produire une graine à fort effet avalanche pour le PRNG
  // de permutation, PAS de protéger la confidentialité du contenu (c'est
  // déjà le travail d'AES-256-GCM / RSA-OAEP en amont).
  function deriveSeed(passphrase) {
    const bytes = new TextEncoder().encode(String(passphrase || ""));
    let h1 = 0x811c9dc5;
    let h2 = 0x9e3779b9;
    for (let i = 0; i < bytes.length; i++) {
      h1 ^= bytes[i];
      h1 = Math.imul(h1, 0x01000193);
      h2 = (h2 ^ bytes[i]) + ((h2 << 5) - h2 + bytes[i]);
      h2 |= 0;
    }
    for (let i = 0; i < 8; i++) {
      h1 = Math.imul(h1 ^ (h1 >>> 15), 0x2c1b3c6d);
      h2 = Math.imul(h2 ^ (h2 >>> 13), 0x297a2d39);
    }
    return ((h1 ^ h2) >>> 0) || 0x2545f491;
  }

  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Permutation complète (Fisher-Yates) des positions de bits utilisables,
  // entièrement déterminée par la clé partagée : sans elle, un tiers ne sait
  // ni où commencer, ni dans quel ordre les bits utiles s'enchaînent.
  function buildOrder(totalPositions, passphrase) {
    const rnd = mulberry32(deriveSeed(passphrase));
    const order = new Uint32Array(totalPositions);
    for (let i = 0; i < totalPositions; i++) order[i] = i;
    for (let i = totalPositions - 1; i > 0; i--) {
      const j = Math.floor(rnd() * (i + 1));
      const tmp = order[i];
      order[i] = order[j];
      order[j] = tmp;
    }
    return order;
  }

  // ---------------------------------------------------------------------
  // Positions utilisables : canaux R, G, B de chaque pixel (alpha préservé)
  // ---------------------------------------------------------------------
  function usablePositions(imageData) {
    const total = Math.floor(imageData.data.length / 4) * 3;
    const positions = new Uint32Array(total);
    let k = 0;
    for (let i = 0; i < imageData.data.length; i++) {
      if ((i + 1) % 4 === 0) continue; // canal alpha jamais touché
      positions[k++] = i;
    }
    return positions;
  }

  function capacityBytes(imageData) {
    const totalBits = usablePositions(imageData).length;
    const budgetBits = Math.floor(totalBits / 8) * 8;
    return Math.max(0, Math.floor((budgetBits - HEADER_BITS) / 8));
  }

  function targetBudgetBytes(payloadLength, capacity) {
    const need = Math.ceil(HEADER_BITS / 8) + payloadLength;
    const rounded = Math.ceil(need / PAD_BLOCK) * PAD_BLOCK;
    return Math.min(Math.max(rounded, PAD_BLOCK), capacity + Math.ceil(HEADER_BITS / 8));
  }

  // ---------------------------------------------------------------------
  // LSB matching (±1) : si le bit LSB courant ne correspond pas au bit
  // voulu, on modifie la valeur de ±1 (sens choisi aléatoirement, borné
  // 0..255) plutôt que de forcer le bit — signature statistique bien plus
  // faible que le LSB replacement classique.
  // ---------------------------------------------------------------------
  function setLsbMatching(data, pos, bit, rnd) {
    const cur = data[pos];
    if ((cur & 1) === bit) return; // rien à faire, aucune trace ajoutée
    if (cur === 0) data[pos] = 1;
    else if (cur === 255) data[pos] = 254;
    else data[pos] = cur + (rnd() < 0.5 ? 1 : -1);
  }

  function embed(imageData, payloadBytes, passphrase) {
    if (!(payloadBytes instanceof Uint8Array)) payloadBytes = new Uint8Array(payloadBytes);
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");

    const capacity = capacityBytes(imageData);
    if (payloadBytes.length > capacity) {
      throw new Error(
        `données trop volumineuses pour cette image (capacité ${capacity} octets, besoin ${payloadBytes.length} octets)`
      );
    }

    const budgetBytes = targetBudgetBytes(payloadBytes.length, capacity);
    const frame = new Uint8Array(budgetBytes);
    frame[0] = (payloadBytes.length >>> 24) & 0xff;
    frame[1] = (payloadBytes.length >>> 16) & 0xff;
    frame[2] = (payloadBytes.length >>> 8) & 0xff;
    frame[3] = payloadBytes.length & 0xff;
    frame.set(payloadBytes, 4);
    // bourrage aléatoire jusqu'au budget fixe : masque la taille réelle du
    // message et rend le volume de bits modifiés constant, indépendant du
    // contenu envoyé.
    const pad = frame.subarray(4 + payloadBytes.length);
    crypto.getRandomValues(pad);

    const positions = usablePositions(imageData);
    const order = buildOrder(positions.length, passphrase);
    const rnd = mulberry32(deriveSeed(passphrase + "#matching"));

    const totalBits = frame.length * 8;
    for (let bitIndex = 0; bitIndex < totalBits; bitIndex++) {
      const byte = frame[bitIndex >> 3];
      const bit = (byte >> (7 - (bitIndex & 7))) & 1;
      const pos = positions[order[bitIndex]];
      setLsbMatching(imageData.data, pos, bit, rnd);
    }
  }

  function extract(imageData, passphrase) {
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");

    const positions = usablePositions(imageData);
    const order = buildOrder(positions.length, passphrase);
    const data = imageData.data;

    function readBits(count, fromBit) {
      const out = new Uint8Array(Math.ceil(count / 8));
      for (let i = 0; i < count; i++) {
        const pos = positions[order[fromBit + i]];
        const bit = data[pos] & 1;
        out[i >> 3] |= bit << (7 - (i & 7));
      }
      return out;
    }

    const header = readBits(HEADER_BITS, 0);
    const payloadLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
    const capacity = capacityBytes(imageData);

    if (payloadLength < 0 || payloadLength > capacity) {
      throw new Error(
        "clé de dissimulation incorrecte ou support non modifié (longueur extraite invalide)"
      );
    }

    return readBits(payloadLength * 8, HEADER_BITS).subarray(0, payloadLength);
  }

  return {
    capacityBytes,
    embed,
    extract,
  };
})();
