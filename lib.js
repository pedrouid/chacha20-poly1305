import { toString } from "uint8arrays/to-string";
import { fromString } from "uint8arrays/from-string";
import { concat } from "uint8arrays/concat";

import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import * as x25519 from "@stablelib/x25519";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";

export function deriveSharedKey(privateKey, publicKey) {
  return x25519.sharedKey(privateKey, publicKey);
}

export function deriveSymKey(sharedKey) {
  const hkdf = new HKDF(SHA256, sharedKey);
  const symKey = hkdf.expand(32);
  return symKey;
}

export function encrypt(symKey, plaintext, iv) {
  const box = new ChaCha20Poly1305(symKey);
  const sealed = box.seal(iv, plaintext);
  return sealed;
}

export function decrypt(symKey, sealed, iv) {
  const box = new ChaCha20Poly1305(symKey);
  const plaintext = box.open(iv, sealed);
  return plaintext;
}

export function serialize(sealed, iv) {
  return toString(concat([iv, sealed]), "base64");
}

export function deserialize(encoded) {
  const array = fromString(encoded, "base64");
  const iv = array.slice(0, 12);
  const sealed = array.slice(12);
  return { sealed, iv };
}
