window.MediaContainerSteganography = (() => {
  // ---------------------------------------------------------------------
  // Dissimulation dans un conteneur MP4 (ISO-BMFF) : au lieu d'ajouter les
  // données chiffrées après la fin du fichier (détectable en une ligne :
  // taille de fichier anormale, octets après le dernier atome reconnu),
  // on insère une "box" ISO-BMFF supplémentaire au milieu du conteneur.
  // C'est un mécanisme prévu par le format lui-même (comme les atomes
  // 'free'/'skip'/'uuid') : tout lecteur vidéo conforme doit ignorer les
  // types de box qu'il ne reconnaît pas, donc la vidéo reste parfaitement
  // lisible. Le nom de la box et sa position parmi les box existantes sont
  // dérivés de la clé de dissimulation partagée, et son contenu est
  // masqué par un flux XOR dérivé de la même clé (le payload réel reste,
  // lui, le JSON chiffré AES/RSA produit en amont).
  //
  // Limite assumée : ceci reste une dissimulation au niveau du conteneur,
  // pas dans la donnée vidéo compressée elle-même (contrairement au canal
  // image, qui modifie les pixels). Un analyste qui parcourt froidement
  // l'arbre des box peut repérer une box inconnue à forte entropie. C'est
  // nettement moins détectable qu'un simple ajout en fin de fichier, mais
  // ce n'est pas équivalent à la robustesse du canal image.
  // ---------------------------------------------------------------------

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

  function boxTypeFromKey(passphrase) {
    const rnd = mulberry32(deriveSeed(passphrase + "#boxtype"));
    const letters = "abcdefghijklmnopqrstuvwxyz0123456789";
    let type = "";
    for (let i = 0; i < 4; i++) type += letters[Math.floor(rnd() * letters.length)];
    return type;
  }

  function keystream(passphrase, length) {
    const rnd = mulberry32(deriveSeed(passphrase + "#stream"));
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = Math.floor(rnd() * 256);
    return out;
  }

  function xorWith(bytes, key) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i];
    return out;
  }

  // Parcours des box de premier niveau (structure ISO-BMFF standard :
  // taille 4 octets + type 4 octets, avec gestion de la taille étendue
  // 64 bits et de la taille 0 = "jusqu'à la fin du fichier").
  function parseTopBoxes(bytes) {
    const boxes = [];
    let offset = 0;
    while (offset + 8 <= bytes.length) {
      let size = readUint32(bytes, offset);
      const type = readAscii(bytes, offset + 4, 4);
      let headerSize = 8;

      if (size === 1) {
        if (offset + 16 > bytes.length) break;
        const hi = readUint32(bytes, offset + 8);
        const lo = readUint32(bytes, offset + 12);
        size = hi * 4294967296 + lo;
        headerSize = 16;
      } else if (size === 0) {
        size = bytes.length - offset;
      }

      if (size < headerSize || offset + size > bytes.length) break;
      boxes.push({ type, start: offset, size, headerSize });
      offset += size;
    }
    return { boxes, consumedAll: offset === bytes.length };
  }

  function assertValidMp4(bytes) {
    const { boxes, consumedAll } = parseTopBoxes(bytes);
    if (!consumedAll || boxes.length === 0 || boxes[0].type !== "ftyp") {
      throw new Error(
        "conteneur non reconnu comme MP4 (ISO-BMFF) valide — utilisez un fichier .mp4 pour la dissimulation vidéo robuste"
      );
    }
    return boxes;
  }

  // Boxes "conteneur" ISO-BMFF dont le corps est lui-même une suite de box
  // (celles qui nous intéressent pour retrouver les tables d'offsets).
  const CONTAINER_TYPES = new Set(["moov", "trak", "mdia", "minf", "stbl", "edts", "mvex"]);

  // stco/co64 stockent des offsets ABSOLUS (depuis le début du fichier) vers
  // chaque sample vidéo/audio dans 'mdat'. Si on insère notre box AVANT ces
  // données, tous ces offsets doivent être décalés de +boxSize, sinon le
  // fichier ne décode plus (NAL units lues au mauvais endroit). On les
  // retrouve en parcourant récursivement moov > trak > mdia > minf > stbl.
  function findOffsetTables(bytes, box, out) {
    if (box.type === "stco" || box.type === "co64") {
      out.push(box);
      return;
    }
    if (!CONTAINER_TYPES.has(box.type)) return;
    const bodyStart = box.start + box.headerSize;
    const bodyEnd = box.start + box.size;
    const { boxes: children } = parseTopBoxes(bytes.subarray(bodyStart, bodyEnd));
    for (const child of children) {
      findOffsetTables(bytes, { ...child, start: child.start + bodyStart }, out);
    }
  }

  function patchOffsetTable(bytes, box, delta) {
    const bodyStart = box.start + box.headerSize;
    const entryCount = readUint32(bytes, bodyStart + 4);
    if (box.type === "stco") {
      let p = bodyStart + 8;
      for (let i = 0; i < entryCount; i++, p += 4) {
        writeUint32(bytes, p, (readUint32(bytes, p) + delta) >>> 0);
      }
    } else {
      // co64 : offsets 64 bits (grosses vidéos) — on ajoute delta sur la
      // partie basse en gérant la retenue sur la partie haute.
      let p = bodyStart + 8;
      for (let i = 0; i < entryCount; i++, p += 8) {
        const hi = readUint32(bytes, p);
        const lo = readUint32(bytes, p + 4);
        const sum = lo + delta;
        writeUint32(bytes, p, (hi + (sum > 0xffffffff ? 1 : 0)) >>> 0);
        writeUint32(bytes, p + 4, sum >>> 0);
      }
    }
  }

  function embed(carrierBuffer, payloadBytes, passphrase) {
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");
    const carrier = toUint8Array(carrierBuffer);
    const boxes = assertValidMp4(carrier);
    const payload = toUint8Array(payloadBytes);

    const frame = new Uint8Array(4 + payload.length);
    frame[0] = (payload.length >>> 24) & 0xff;
    frame[1] = (payload.length >>> 16) & 0xff;
    frame[2] = (payload.length >>> 8) & 0xff;
    frame[3] = payload.length & 0xff;
    frame.set(payload, 4);
    const masked = xorWith(frame, keystream(passphrase, frame.length));

    const boxType = boxTypeFromKey(passphrase);
    const boxSize = 8 + masked.length;
    const newBox = new Uint8Array(boxSize);
    writeUint32(newBox, 0, boxSize);
    newBox.set(new TextEncoder().encode(boxType), 4);
    newBox.set(masked, 8);

    // Position d'insertion dérivée de la clé : quelque part parmi les box
    // existantes (jamais avant 'ftyp'), pour ne pas laisser de motif
    // "toujours collé en bout de fichier" repérable d'un coup d'œil. Si un
    // seul 'mdat' est présent, toute position est possible : on repatche
    // les tables d'offsets ci-dessous. Sinon (structure non standard, ex.
    // MP4 fragmenté à plusieurs 'mdat'), on reste prudent et on insère
    // uniquement après le dernier bloc, sans rien patcher.
    const mdatBoxes = boxes.filter((b) => b.type === "mdat");
    const rnd = mulberry32(deriveSeed(passphrase + "#position"));

    let insertOffset;
    if (mdatBoxes.length === 1) {
      const insertAfterIndex = 1 + Math.floor(rnd() * boxes.length);
      insertOffset = insertAfterIndex < boxes.length ? boxes[insertAfterIndex].start : carrier.length;
    } else {
      insertOffset = carrier.length;
    }
    const shiftsSampleData = mdatBoxes.length === 1 && insertOffset <= mdatBoxes[0].start;

    const output = new Uint8Array(carrier.length + boxSize);
    output.set(carrier.subarray(0, insertOffset), 0);
    output.set(newBox, insertOffset);
    output.set(carrier.subarray(insertOffset), insertOffset + boxSize);

    if (shiftsSampleData) {
      const { boxes: newTopBoxes } = parseTopBoxes(output);
      const moov = newTopBoxes.find((b) => b.type === "moov");
      if (moov) {
        const tables = [];
        findOffsetTables(output, moov, tables);
        for (const t of tables) patchOffsetTable(output, t, boxSize);
      }
    }

    return output.buffer;
  }

  function extract(carrierBuffer, passphrase) {
    if (!passphrase) throw new Error("clé de dissimulation partagée requise");
    const bytes = toUint8Array(carrierBuffer);
    const boxes = assertValidMp4(bytes);
    const boxType = boxTypeFromKey(passphrase);

    const match = boxes.find((b) => b.type === boxType);
    if (!match) {
      throw new Error("clé de dissimulation incorrecte ou support non modifié");
    }

    const masked = bytes.slice(match.start + match.headerSize, match.start + match.size);
    const frame = xorWith(masked, keystream(passphrase, masked.length));
    const payloadLength = (frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];

    if (payloadLength < 0 || 4 + payloadLength > frame.length) {
      throw new Error("clé de dissimulation incorrecte ou support non modifié");
    }

    return frame.subarray(4, 4 + payloadLength);
  }

  function readAscii(bytes, offset, length) {
    let text = "";
    for (let i = 0; i < length; i++) text += String.fromCharCode(bytes[offset + i]);
    return text;
  }

  function writeUint32(bytes, offset, value) {
    bytes[offset] = (value >>> 24) & 0xff;
    bytes[offset + 1] = (value >>> 16) & 0xff;
    bytes[offset + 2] = (value >>> 8) & 0xff;
    bytes[offset + 3] = value & 0xff;
  }

  function readUint32(bytes, offset) {
    return (
      ((bytes[offset] << 24) >>> 0) +
      (bytes[offset + 1] << 16) +
      (bytes[offset + 2] << 8) +
      bytes[offset + 3]
    );
  }

  function toUint8Array(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new Error("donnees binaires invalides");
  }

  return {
    embed,
    extract,
  };
})();
