// AES that matches AMPscript's EncryptSymmetric / DecryptSymmetric with "aes".
//
// Marketing Cloud derives a 256-bit key from the password and salt with
// PBKDF2 (HMAC-SHA1, 1000 iterations), then uses AES-256-CBC with PKCS#7
// padding. The salt and IV are hex strings, and the ciphertext is Base64.
//
//   AMPscript: DecryptSymmetric(@cipher, "aes", @null, @password, @null, @salt, @null, @iv)
//   Node:      decrypt(cipher, { password, salt, iv })
//
// No dependencies: Node's built-in crypto only.
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';

const ITERATIONS = 1000;
const KEY_BYTES = 32;
const HEX = /^[0-9a-fA-F]+$/;

function check({ password, salt, iv }) {
  if (typeof password !== 'string' || !password) throw new TypeError('password must be a non-empty string');
  if (typeof salt !== 'string' || !HEX.test(salt) || salt.length % 2) throw new TypeError('salt must be a hex string (8 bytes = 16 hex characters is typical)');
  if (typeof iv !== 'string' || !HEX.test(iv) || iv.length !== 32) throw new TypeError('iv must be 16 bytes as 32 hex characters');
}

export function deriveKey(password, salt) {
  return pbkdf2Sync(password, Buffer.from(salt, 'hex'), ITERATIONS, KEY_BYTES, 'sha1');
}

// Encrypts UTF-8 text. The result can be decrypted by DecryptSymmetric.
export function encrypt(text, options) {
  check(options);
  const cipher = createCipheriv('aes-256-cbc', deriveKey(options.password, options.salt), Buffer.from(options.iv, 'hex'));
  return Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]).toString('base64');
}

// Decrypts Base64 from EncryptSymmetric (or from encrypt above) to UTF-8 text.
export function decrypt(base64, options) {
  check(options);
  const decipher = createDecipheriv('aes-256-cbc', deriveKey(options.password, options.salt), Buffer.from(options.iv, 'hex'));
  return Buffer.concat([decipher.update(String(base64), 'base64'), decipher.final()]).toString('utf8');
}

// New random salt (8 bytes) and IV (16 bytes) as hex, ready for both sides.
export function randomSaltAndIv() {
  return { salt: randomBytes(8).toString('hex'), iv: randomBytes(16).toString('hex') };
}
