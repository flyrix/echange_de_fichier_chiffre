/**
 * Moteur cryptographique - execute entierement dans le navigateur
 * via l'API native Web Crypto (window.crypto.subtle).
 *
 * Schema hybride, identique dans son principe a PGP / TLS :
 *   - RSA-OAEP (2048 bits)  -> chiffre/dechiffre une petite cle AES
 *   - AES-256-GCM           -> chiffre/dechiffre le contenu reel
 *     (rapide, et le mode GCM fournit en prime un tag d'integrite :
 *      toute alteration du ciphertext fait echouer le dechiffrement)
 *
 * Pourquoi hybride et pas RSA seul ?
 *   RSA ne peut chiffrer que de tres petites quantites de donnees
 *   (quelques centaines d'octets) et est lent. On l'utilise donc
 *   uniquement pour proteger la cle AES, qui elle chiffre le vrai
 *   contenu, quelle que soit sa taille.
 */

const CryptoEngine = (() => {
  const RSA_PARAMS = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  };

  // ---------- Utilitaires encodage ----------

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  // ---------- Generation et gestion des cles ----------

  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
    const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { publicKeyJwk, privateKeyJwk };
  }

  async function importPublicKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  }

  async function importPrivateKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  }

  // ---------- Chiffrement (cote expediteur) ----------

  /**
   * Chiffre un ArrayBuffer pour un destinataire donne.
   * Retourne les champs prets a etre envoyes au serveur (tous en base64).
   */
  async function encryptForRecipient(dataBuffer, recipientPublicKeyJwk) {
    // 1. Cle AES ephemere, unique pour ce message
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);

    // 2. IV aleatoire (12 octets recommandes pour GCM), jamais reutilise
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 3. Chiffrement du contenu reel avec AES-GCM
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);

    // 4. Export de la cle AES brute, puis chiffrement de cette cle avec la
    //    cle PUBLIQUE RSA du destinataire : lui seul pourra la recuperer.
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    const recipientPublicKey = await importPublicKey(recipientPublicKeyJwk);
    const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawAesKey);

    return {
      iv: bufToB64(iv),
      encryptedKey: bufToB64(encryptedKey),
      ciphertext: bufToB64(ciphertext),
    };
  }

  // ---------- Dechiffrement (cote destinataire) ----------

  /**
   * Dechiffre un message recu, en utilisant la cle privee RSA du
   * destinataire (jamais transmise au serveur).
   */
  async function decryptMessage({ iv, encryptedKey, ciphertext }, recipientPrivateKeyJwk) {
    const privateKey = await importPrivateKey(recipientPrivateKeyJwk);

    // 1. Recuperer la cle AES en la dechiffrant avec la cle privee RSA
    const rawAesKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64ToBuf(encryptedKey));
    const aesKey = await crypto.subtle.importKey("raw", rawAesKey, "AES-GCM", true, ["decrypt"]);

    // 2. Dechiffrer le contenu reel. Si le message a ete altere (integrite),
    //    ou que la mauvaise cle est utilisee, cet appel leve une exception.
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBuf(iv) },
      aesKey,
      b64ToBuf(ciphertext)
    );
    return plaintext; // ArrayBuffer
  }

  return {
    generateKeyPair,
    encryptForRecipient,
    decryptMessage,
    bufToB64,
    b64ToBuf,
  };
})();
