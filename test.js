import * as encoding from "@walletconnect/encoding";
// import { randomBytes } from "@walletconnect/randombytes";
import { fromString } from "uint8arrays/from-string";
import { toString } from "uint8arrays/to-string";

import {
  deriveSharedKey,
  deriveSymKey,
  encrypt,
  decrypt,
  serialize,
} from "./lib.js";

const keyPair = {
  A: {
    privateKey: encoding.hexToArray(
      "1fb63fca5c6ac731246f2f069d3bc2454345d5208254aa8ea7bffc6d110c8862"
    ),
    publicKey: encoding.hexToArray(
      "ff7a7d5767c362b0a17ad92299ebdb7831dcbd9a56959c01368c7404543b3342"
    ),
  },
  B: {
    privateKey: encoding.hexToArray(
      "36bf507903537de91f5e573666eaa69b1fa313974f23b2b59645f20fea505854"
    ),
    publicKey: encoding.hexToArray(
      "590c2c627be7af08597091ff80dd41f7fa28acd10ef7191d7e830e116d3a186a"
    ),
  },
};

const expected = {
  sharedKey: encoding.hexToArray(
    "9c87e48e69b33a613907515bcd5b1b4cc10bbaf15167b19804b00f0a9217e607"
  ),
  symKey: encoding.hexToArray(
    "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c"
  ),
  iv: encoding.hexToArray("717765636661617364616473"),
  sealed: encoding.hexToArray(
    "56191b8c7aa58bc84dd2b15b02d30f22c261a38ccbbd6b2431340a486c"
  ),
  plaintext: "WalletConnect",
};

const sharedKey = deriveSharedKey(keyPair.B.privateKey, keyPair.A.publicKey);
const sharedKeyHex = encoding.arrayToHex(sharedKey);
console.log("sharedKey", sharedKeyHex);

const symKey = deriveSymKey(sharedKey);
const symKeyHex = encoding.arrayToHex(symKey);
console.log("symKey", symKeyHex);
const iv = expected.iv;
const sealed = encrypt(symKey, fromString("WalletConnect", "utf8"), iv);
console.log("encrypted", serialize(sealed, iv));
const plaintext = decrypt(symKey, sealed, iv);
console.log("decrypted", toString(plaintext, "utf8"));
