// =========================================================================
// Boîte à outils de stéganalyse — détection statistique/structurelle de
// dissimulation, SANS connaître ni la clé ni le message. Aucune de ces
// techniques ne "casse" un chiffrement : elles cherchent seulement des
// anomalies qui trahissent la PRÉSENCE de données cachées.
//
// Techniques implémentées, volontairement indépendantes les unes des
// autres (pour croiser les indices plutôt que se fier à un seul signal) :
//   - Image : plan de bits LSB (attaque visuelle), test du χ² de
//     Westfeld-Pfitzmann (Paires de Valeurs), test du "monobit" (ratio de
//     LSB à 1), test des séries ("runs test", NIST SP 800-22) sur le plan
//     de bits LSB, histogramme des valeurs.
//   - Audio WAV : mêmes tests statistiques appliqués aux échantillons PCM.
//   - Conteneurs (PNG/WAV/MP4) : vérification de cohérence structurelle —
//     octets superflus après la fin logique du fichier (signature
//     classique d'un ajout brut de données), boîtes MP4 inconnues à forte
//     entropie.
//   - Tout fichier : entropie de Shannon globale.
// =========================================================================
window.Steganalysis = (() => {
  // -----------------------------------------------------------------
  // Primitives statistiques génériques (indépendantes du format)
  // -----------------------------------------------------------------

  function lsbRatio(values) {
    let ones = 0;
    for (let i = 0; i < values.length; i++) ones += values[i] & 1;
    return values.length ? ones / values.length : 0;
  }

  // Test des séries (NIST SP 800-22 "Runs Test") appliqué à la séquence
  // des bits de poids faible. Une image/un son naturel a des LSB corrélés
  // au contenu (peu de vrais "runs" alternés) ; des données chiffrées
  // dissimulées se comportent, elles, comme une suite de bits indépendants
  // — la longueur/le nombre de séries s'en trouve statistiquement modifié.
  function runsTest(values) {
    const n = values.length;
    if (n < 2) return { z: 0, runs: 0, pi: 0.5, suspicious: false };

    let ones = 0;
    for (let i = 0; i < n; i++) ones += values[i] & 1;
    const pi = ones / n;

    // Pré-requis classique du test : la proportion doit être assez proche
    // de 0.5, sinon le test n'est pas applicable (le déséquilibre global
    // suffit déjà à conclure, cf. lsbRatio).
    if (Math.abs(pi - 0.5) > 2 / Math.sqrt(n)) {
      return { z: null, runs: null, pi, suspicious: false, notApplicable: true };
    }

    let runs = 1;
    for (let i = 1; i < n; i++) {
      if ((values[i] & 1) !== (values[i - 1] & 1)) runs++;
    }

    const expected = 2 * n * pi * (1 - pi);
    const variance = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
    const z = variance > 0 ? (runs - expected) / variance : 0;

    // |z| > ~2.58 correspond à un rejet de l'hypothèse "séquence aléatoire
    // indépendante" au seuil de confiance de 99 %.
    return { z, runs, pi, suspicious: Math.abs(z) > 2.58 };
  }

  // Test du χ² de Westfeld & Pfitzmann ("Pairs of Values") : sous LSB
  // replacement, les fréquences des valeurs adjacentes (2i, 2i+1)
  // devraient devenir quasi égales dans la zone modifiée. On calcule la
  // p-value sur des fenêtres croissantes du fichier pour repérer une
  // éventuelle frontière "zone modifiée / zone intacte" — signature
  // typique d'un embarquement séquentiel naïf.
  function slidingChiSquareAttack(values, steps = 30) {
    if (!values.length) return [{ percent: 100, pValue: 0 }];

    const pointCount = Math.max(1, steps);
    const results = [];
    for (let step = 1; step <= pointCount; step++) {
      const percent = (step / pointCount) * 100;
      const count = Math.max(1, Math.floor((values.length * percent) / 100));
      results.push({ percent, pValue: chiSquarePValue(values, count) });
    }
    return results;
  }

  function chiSquarePValue(values, count) {
    const histogram = new Uint32Array(256);
    for (let i = 0; i < count; i++) histogram[values[i]]++;

    let chi = 0;
    let degrees = 0;
    for (let value = 0; value < 256; value += 2) {
      const even = histogram[value];
      const odd = histogram[value + 1];
      const expected = (even + odd) / 2;
      if (expected <= 0) continue;
      chi += ((even - expected) ** 2) / expected;
      chi += ((odd - expected) ** 2) / expected;
      degrees++;
    }

    if (degrees === 0) return 0;
    return clamp01(regularizedGammaQ(degrees / 2, chi / 2));
  }

  function histogram256(values) {
    const h = new Uint32Array(256);
    for (let i = 0; i < values.length; i++) h[values[i]]++;
    return h;
  }

  function shannonEntropy(bytes) {
    if (!bytes.length) return 0;
    const counts = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (!counts[i]) continue;
      const p = counts[i] / bytes.length;
      entropy -= p * Math.log2(p);
    }
    return entropy; // 0 (très structuré) .. 8 (indiscernable d'aléatoire)
  }

  // -----------------------------------------------------------------
  // Image (canvas ImageData)
  // -----------------------------------------------------------------

  function validateChannel(channel) {
    if (!Number.isInteger(channel) || channel < 0 || channel > 2) {
      throw new Error("canal couleur invalide");
    }
  }

  function channelValues(imageData, channel) {
    validateChannel(channel);
    const values = new Uint8Array(Math.floor(imageData.data.length / 4));
    let out = 0;
    for (let i = 0; i < imageData.data.length; i += 4) values[out++] = imageData.data[i + channel];
    return values;
  }

  function extractBitPlane(imageData, channel = 2) {
    validateChannel(channel);
    const output = new ImageData(imageData.width, imageData.height);
    const src = imageData.data;
    const dst = output.data;
    for (let i = 0; i < src.length; i += 4) {
      const value = src[i + channel] & 1 ? 255 : 0;
      dst[i] = value;
      dst[i + 1] = value;
      dst[i + 2] = value;
      dst[i + 3] = 255;
    }
    return output;
  }

  // Analyse complète d'une image : exécute chaque test sur les 3 canaux
  // et renvoie une synthèse exploitable directement par l'UI.
  // Un embarquement séquentiel naïf ne couvre souvent qu'une partie du
  // fichier : la p-value CUMULÉE finale (sur 100 % du fichier) peut alors
  // rester basse même si une portion est clairement modifiée, car le
  // signal se dilue dans la zone intacte restante. On regarde donc
  // l'existence d'un plateau soutenu de p-values élevées quelque part
  // dans la courbe, pas seulement le dernier point.
  function chiCurveHasSustainedPlateau(curve, threshold = 0.9, minShare = 0.15) {
    const hits = curve.filter((p) => p.pValue > threshold).length;
    return hits / curve.length >= minShare;
  }

  function analyzeImage(imageData) {
    const channels = ["R", "G", "B"];
    const perChannel = channels.map((label, idx) => {
      const values = channelValues(imageData, idx);
      const chi = slidingChiSquareAttack(values, 30);
      const finalChi = chi[chi.length - 1].pValue;
      const plateau = chiCurveHasSustainedPlateau(chi);
      const runs = runsTest(values);
      const ratio = lsbRatio(values);
      return {
        channel: label,
        chiSquareCurve: chi,
        chiSquareFinalPValue: finalChi,
        chiSquarePlateauDetected: plateau,
        runsTest: runs,
        lsbRatio: ratio,
        histogram: histogram256(values),
        suspicious: finalChi > 0.9 || plateau || runs.suspicious === true || Math.abs(ratio - 0.5) > 0.02,
      };
    });

    return {
      type: "image",
      perChannel,
      overallSuspicious: perChannel.some((c) => c.suspicious),
    };
  }

  // -----------------------------------------------------------------
  // Audio WAV (ArrayBuffer/Uint8Array)
  // -----------------------------------------------------------------

  function findWavDataChunk(bytes) {
    if (bytes.length < 12 || readAscii(bytes, 0, 4) !== "RIFF" || readAscii(bytes, 8, 4) !== "WAVE") {
      return null;
    }
    let offset = 12;
    while (offset + 8 <= bytes.length) {
      const id = readAscii(bytes, offset, 4);
      const size = readUint32LE(bytes, offset + 4);
      const dataOffset = offset + 8;
      if (dataOffset + size > bytes.length) break;
      if (id === "data") return { offset: dataOffset, size };
      offset = dataOffset + size + (size % 2);
    }
    return null;
  }

  function analyzeWav(bytes) {
    const declaredSize = bytes.length >= 8 ? readUint32LE(bytes, 4) + 8 : null;
    const sizeMismatch = declaredSize !== null && declaredSize !== bytes.length;

    const dataChunk = findWavDataChunk(bytes);
    if (!dataChunk) {
      return {
        type: "wav",
        valid: false,
        message: "en-tête WAV/RIFF non reconnu (fichier compressé ou corrompu)",
      };
    }

    const pcm = bytes.subarray(dataChunk.offset, dataChunk.offset + dataChunk.size);
    const chi = slidingChiSquareAttack(pcm, 30);
    const finalChi = chi[chi.length - 1].pValue;
    const plateau = chiCurveHasSustainedPlateau(chi);
    const runs = runsTest(pcm);
    const ratio = lsbRatio(pcm);

    // Octets présents après la fin déclarée du chunk 'data' : signature
    // classique d'un ajout brut de données en fin de fichier.
    const trailingBytes = Math.max(0, bytes.length - (dataChunk.offset + dataChunk.size));

    return {
      type: "wav",
      valid: true,
      chiSquareCurve: chi,
      chiSquareFinalPValue: finalChi,
      chiSquarePlateauDetected: plateau,
      runsTest: runs,
      lsbRatio: ratio,
      histogram: histogram256(pcm),
      sizeMismatch,
      trailingBytes,
      suspicious:
        finalChi > 0.9 || plateau || runs.suspicious === true || Math.abs(ratio - 0.5) > 0.02 || trailingBytes > 0,
    };
  }

  // -----------------------------------------------------------------
  // Conteneur MP4 (ISO-BMFF)
  // -----------------------------------------------------------------

  const KNOWN_MP4_BOX_TYPES = new Set([
    "ftyp", "moov", "mdat", "free", "skip", "wide", "mdia", "trak", "minf",
    "stbl", "stco", "co64", "stsz", "stsc", "stts", "stsd", "stss", "ctts",
    "edts", "elst", "mvhd", "tkhd", "hdlr", "vmhd", "smhd", "dinf", "dref",
    "udta", "meta", "mvex", "mfra", "sidx", "uuid", "iods", "pasp", "colr",
    "btrt",
  ]);

  function parseMp4TopBoxes(bytes) {
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
    return { boxes, consumedAll: offset === bytes.length, stoppedAt: offset };
  }

  function analyzeMp4(bytes) {
    const { boxes, consumedAll, stoppedAt } = parseMp4TopBoxes(bytes);
    const isMp4 = boxes.length > 0 && boxes[0].type === "ftyp";
    if (!isMp4) {
      return { type: "mp4", valid: false, message: "signature ftyp introuvable : pas un MP4/ISO-BMFF standard" };
    }

    const boxReport = boxes.map((b) => {
      const body = bytes.subarray(b.start + b.headerSize, b.start + b.size);
      const entropy = shannonEntropy(body);
      const known = KNOWN_MP4_BOX_TYPES.has(b.type);
      // Une box de padding ('free'/'skip') est censée être peu structurée
      // mais rarement aussi dense en entropie qu'un flux chiffré ; une box
      // de type totalement inconnu, elle, doit toujours interpeller.
      const suspicious = !known || ((b.type === "free" || b.type === "skip") && entropy > 7.5);
      return { type: b.type, size: b.size, entropy: Number(entropy.toFixed(2)), known, suspicious };
    });

    const trailingBytes = consumedAll ? 0 : bytes.length - stoppedAt;

    return {
      type: "mp4",
      valid: true,
      boxes: boxReport,
      trailingBytes,
      suspicious: boxReport.some((b) => b.suspicious) || trailingBytes > 0,
    };
  }

  // -----------------------------------------------------------------
  // PNG : octets après le chunk IEND (fin logique officielle du format)
  // -----------------------------------------------------------------

  const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

  function analyzePngTrailer(bytes) {
    if (bytes.length < 8 || !PNG_SIGNATURE.every((b, i) => bytes[i] === b)) return null;
    let offset = 8;
    while (offset + 8 <= bytes.length) {
      const length = readUint32(bytes, offset);
      const type = readAscii(bytes, offset + 4, 4);
      const chunkEnd = offset + 8 + length + 4; // longueur + type + data + CRC
      if (type === "IEND") {
        const trailingBytes = Math.max(0, bytes.length - chunkEnd);
        return { trailingBytes, suspicious: trailingBytes > 0 };
      }
      if (chunkEnd <= offset) break;
      offset = chunkEnd;
    }
    return null;
  }

  // -----------------------------------------------------------------
  // Point d'entrée générique : détecte le format et route vers la bonne
  // analyse. `mimeType`/`filename` servent d'indices ; le contenu prime.
  // -----------------------------------------------------------------

  function analyzeGenericFile(bytes) {
    const entropy = shannonEntropy(bytes);
    const isPng = bytes.length >= 8 && PNG_SIGNATURE.every((b, i) => bytes[i] === b);
    const isWav = bytes.length >= 12 && readAscii(bytes, 0, 4) === "RIFF" && readAscii(bytes, 8, 4) === "WAVE";
    const isMp4 = bytes.length >= 8 && readAscii(bytes, 4, 4) === "ftyp";

    if (isWav) return { ...analyzeWav(bytes), globalEntropy: entropy };
    if (isMp4) return { ...analyzeMp4(bytes), globalEntropy: entropy };
    if (isPng) {
      const trailer = analyzePngTrailer(bytes);
      return {
        type: "png-generic",
        globalEntropy: entropy,
        trailer,
        suspicious: !!(trailer && trailer.suspicious) || entropy > 7.9,
      };
    }
    return {
      type: "unknown",
      globalEntropy: entropy,
      suspicious: entropy > 7.9,
      message: "format non reconnu par les analyseurs dédiés — seule l'entropie globale a été mesurée",
    };
  }

  // -----------------------------------------------------------------
  // Helpers bas niveau
  // -----------------------------------------------------------------

  function regularizedGammaQ(a, x) {
    if (x < 0 || a <= 0) return NaN;
    if (x === 0) return 1;
    if (x < a + 1) return 1 - regularizedGammaPSeries(a, x);

    const fpmin = 1e-30;
    const eps = 1e-10;
    let b = x + 1 - a;
    let c = 1 / fpmin;
    let d = 1 / b;
    let h = d;
    for (let i = 1; i <= 100; i++) {
      const an = -i * (i - a);
      b += 2;
      d = an * d + b;
      if (Math.abs(d) < fpmin) d = fpmin;
      c = b + an / c;
      if (Math.abs(c) < fpmin) c = fpmin;
      d = 1 / d;
      const delta = d * c;
      h *= delta;
      if (Math.abs(delta - 1) < eps) break;
    }
    return Math.exp(-x + a * Math.log(x) - logGamma(a)) * h;
  }

  function regularizedGammaPSeries(a, x) {
    const eps = 1e-10;
    let sum = 1 / a;
    let del = sum;
    let ap = a;
    for (let n = 1; n <= 100; n++) {
      ap++;
      del *= x / ap;
      sum += del;
      if (Math.abs(del) < Math.abs(sum) * eps) break;
    }
    return sum * Math.exp(-x + a * Math.log(x) - logGamma(a));
  }

  function logGamma(z) {
    const coefficients = [
      676.5203681218851, -1259.1392167224028, 771.3234287776531, -176.6150291621406,
      12.507343278686905, -0.13857109526572012, 9.984369578019572e-6, 1.5056327351493116e-7,
    ];
    if (z < 0.5) return Math.log(Math.PI) - Math.log(Math.sin(Math.PI * z)) - logGamma(1 - z);
    z -= 1;
    let x = 0.9999999999998099;
    for (let i = 0; i < coefficients.length; i++) x += coefficients[i] / (z + i + 1);
    const t = z + coefficients.length - 0.5;
    return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
  }

  function clamp01(value) {
    if (!Number.isFinite(value)) return 0;
    return Math.min(1, Math.max(0, value));
  }

  function readAscii(bytes, offset, length) {
    let text = "";
    for (let i = 0; i < length; i++) text += String.fromCharCode(bytes[offset + i]);
    return text;
  }

  function readUint32(bytes, offset) {
    return ((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
  }

  function readUint32LE(bytes, offset) {
    return bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + ((bytes[offset + 3] << 24) >>> 0);
  }

  return {
    // primitives (conservées pour compatibilité + tests unitaires)
    extractBitPlane,
    slidingChiSquareAttack,
    lsbRatio,
    runsTest,
    shannonEntropy,
    histogram256,
    // analyses haut niveau
    analyzeImage,
    analyzeWav,
    analyzeMp4,
    analyzePngTrailer,
    analyzeGenericFile,
  };
})();
