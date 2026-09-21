window.AudioSteganography = (() => {
  const HEADER_BITS = 32;
  const PAD_BLOCK = 4096;

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

  function setLsbMatching(bytes, pos, bit, rnd) {
    const cur = bytes[pos];
    if ((cur & 1) === bit) return;
    if (cur === 0) bytes[pos] = 1;
    else if (cur === 255) bytes[pos] = 254;
    else bytes[pos] = cur + (rnd() < 0.5 ? 1 : -1);
  }

  function capacityForSize(dataSize) {
    const budgetBits = Math.floor(dataSize / 8) * 8;
    return Math.max(0, Math.floor((budgetBits - HEADER_BITS) / 8));
  }

  function capacityBytes(wavBuffer) {
    const bytes = toUint8Array(wavBuffer);
    const dataChunk = findDataChunk(bytes);
    return capacityForSize(dataChunk.size);
  }

  function targetBudgetBytes(payloadLength, capacity) {
    const need = Math.ceil(HEADER_BITS / 8) + payloadLength;
    const rounded = Math.ceil(need / PAD_BLOCK) * PAD_BLOCK;
    return Math.min(Math.max(rounded, PAD_BLOCK), capacity + Math.ceil(HEADER_BITS / 8));
  }

  function embed(wavBuffer, payloadBytes, passphrase) {
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");
    const source = toUint8Array(wavBuffer);
    const payload = toUint8Array(payloadBytes);
    const dataChunk = findDataChunk(source);
    const capacity = capacityForSize(dataChunk.size);

    if (payload.length > capacity) {
      throw new Error(
        `audio WAV trop petit (capacite ${capacity} octets, besoin ${payload.length} octets)`
      );
    }

    const budgetBytes = targetBudgetBytes(payload.length, capacity);
    const frame = new Uint8Array(budgetBytes);
    frame[0] = (payload.length >>> 24) & 0xff;
    frame[1] = (payload.length >>> 16) & 0xff;
    frame[2] = (payload.length >>> 8) & 0xff;
    frame[3] = payload.length & 0xff;
    frame.set(payload, 4);
    crypto.getRandomValues(frame.subarray(4 + payload.length));

    const order = buildOrder(dataChunk.size, passphrase);
    const rnd = mulberry32(deriveSeed(passphrase + "#matching"));
    const output = new Uint8Array(source);

    const totalBits = frame.length * 8;
    for (let bitIndex = 0; bitIndex < totalBits; bitIndex++) {
      const byte = frame[bitIndex >> 3];
      const bit = (byte >> (7 - (bitIndex & 7))) & 1;
      const pos = dataChunk.offset + order[bitIndex];
      setLsbMatching(output, pos, bit, rnd);
    }

    return output.buffer;
  }

  function extract(wavBuffer, passphrase) {
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");
    const bytes = toUint8Array(wavBuffer);
    const dataChunk = findDataChunk(bytes);
    const order = buildOrder(dataChunk.size, passphrase);
    const capacity = capacityForSize(dataChunk.size);

    function readBits(count, fromBit) {
      const out = new Uint8Array(Math.ceil(count / 8));
      for (let i = 0; i < count; i++) {
        const pos = dataChunk.offset + order[fromBit + i];
        const bit = bytes[pos] & 1;
        out[i >> 3] |= bit << (7 - (i & 7));
      }
      return out;
    }

    const header = readBits(HEADER_BITS, 0);
    const payloadLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
    if (payloadLength < 0 || payloadLength > capacity) {
      throw new Error("clé de dissimulation incorrecte ou audio non modifié");
    }

    return readBits(payloadLength * 8, HEADER_BITS).subarray(0, payloadLength);
  }

  function findDataChunk(bytes) {
    if (bytes.length < 12 || readAscii(bytes, 0, 4) !== "RIFF" || readAscii(bytes, 8, 4) !== "WAVE") {
      throw new Error("fichier WAV invalide ou compresse");
    }

    let offset = 12;
    while (offset + 8 <= bytes.length) {
      const id = readAscii(bytes, offset, 4);
      const size = readUint32LE(bytes, offset + 4);
      const dataOffset = offset + 8;

      if (dataOffset + size > bytes.length) {
        throw new Error("chunk WAV tronque");
      }
      if (id === "data") {
        return { offset: dataOffset, size };
      }

      offset = dataOffset + size + (size % 2);
    }

    throw new Error("chunk audio WAV introuvable");
  }

  function readAscii(bytes, offset, length) {
    let text = "";
    for (let i = 0; i < length; i++) text += String.fromCharCode(bytes[offset + i]);
    return text;
  }

  function readUint32LE(bytes, offset) {
    return (
      bytes[offset] +
      (bytes[offset + 1] << 8) +
      (bytes[offset + 2] << 16) +
      ((bytes[offset + 3] << 24) >>> 0)
    );
  }

  function toUint8Array(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new Error("donnees binaires invalides");
  }

  return {
    capacityBytes,
    embed,
    extract,
  };
})();
