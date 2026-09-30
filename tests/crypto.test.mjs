import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as acorn from 'acorn';
import { decrypt, encrypt, randomSaltAndIv } from '../aes/sfmc-aes.mjs';

// ---------- AES (AMPscript EncryptSymmetric / DecryptSymmetric) ----------

// Public example from https://salesforce.stackexchange.com/q/384953: this
// ciphertext was decrypted in Marketing Cloud with
// DecryptSymmetric(cipher, "aes", @null, password, @null, salt, @null, iv).
const SE = {
  cipher: 'bfHMgljk/BpHudryDHranBLlEOZevJQvEH7Wj+nZxHNFYFHliBP+Bg9Esb61ZxiJ2AMRpGIknGaWPvvN1QIeUw==',
  plain: 'The quick brown fox jumps over the lazy dog! !@#$%^&*()_+',
  options: { password: 'anypasswordvalue', salt: '701e6a98ec6e4f51', iv: 'c4a89623cbca32fa0a9d077569975fbc' },
};

test('AES: matches the Marketing Cloud example both ways', () => {
  assert.equal(decrypt(SE.cipher, SE.options), SE.plain);
  assert.equal(encrypt(SE.plain, SE.options), SE.cipher);
});

test('AES: round-trips UTF-8 with random salt and IV', () => {
  const options = { password: 'pässwörd', ...randomSaltAndIv() };
  assert.match(options.salt, /^[0-9a-f]{16}$/);
  assert.match(options.iv, /^[0-9a-f]{32}$/);
  for (const text of ['', 'a', 'Olá 🎉 日本語', 'x'.repeat(1000)]) assert.equal(decrypt(encrypt(text, options), options), text);
});

test('AES: rejects bad settings and a wrong password', () => {
  assert.throws(() => encrypt('x', { ...SE.options, iv: 'abc' }), /iv must be/);
  assert.throws(() => encrypt('x', { ...SE.options, salt: 'not-hex' }), /salt must be/);
  assert.throws(() => encrypt('x', { ...SE.options, password: '' }), /password must be/);
  assert.throws(() => decrypt(SE.cipher, { ...SE.options, password: 'wrong' }));
});

// ---------- SSJS HMAC-SHA256 ----------

const source = readFileSync(new URL('../hmac/hmac-sha256.js', import.meta.url), 'utf8');
const { SfmcCrypto: C } = (() => { const ctx = {}; vm.runInNewContext(source, ctx); return ctx; })();
const bytes = hex => [...Buffer.from(hex, 'hex')];
const hex = arr => Buffer.from(arr).toString('hex');

test('SSJS file is valid ES3 and defines one global', () => {
  assert.doesNotThrow(() => acorn.parse(source, { ecmaVersion: 3 }));
  const ctx = {};
  vm.runInNewContext(source, ctx);
  assert.deepEqual(Object.keys(ctx), ['SfmcCrypto']);
});

test('SHA-256: FIPS 180 examples', () => {
  assert.equal(C.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(C.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(C.sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
});

// RFC 4231 section 4 (HMAC-SHA-256 results).
const RFC4231 = [
  ['0b'.repeat(20), Buffer.from('Hi There').toString('hex'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
  [Buffer.from('Jefe').toString('hex'), Buffer.from('what do ya want for nothing?').toString('hex'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
  ['aa'.repeat(20), 'dd'.repeat(50), '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'],
  ['0102030405060708090a0b0c0d0e0f10111213141516171819', 'cd'.repeat(50), '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'],
  ['aa'.repeat(131), Buffer.from('Test Using Larger Than Block-Size Key - Hash Key First').toString('hex'), '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'],
  ['aa'.repeat(131), Buffer.from('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.').toString('hex'), '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2'],
];

test('HMAC-SHA256: RFC 4231 test cases', () => {
  for (const [key, data, expected] of RFC4231) assert.equal(hex(C.hmacSha256Bytes(bytes(key), bytes(data))), expected);
  assert.equal(C.hmacSha256Hex('Jefe', 'what do ya want for nothing?'), RFC4231[1][2]);
  assert.equal(C.hmacSha256HexKey('0b'.repeat(20), 'Hi There'), RFC4231[0][2]);
});

test('HMAC-SHA256: matches Node for 500 random keys and messages, including block-boundary lengths', () => {
  const lengths = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300];
  for (let i = 0; i < 500; i++) {
    const key = randomBytes(i < 100 ? lengths[i % lengths.length] : Math.floor(Math.random() * 200));
    const msg = randomBytes(i < 100 ? lengths[(i * 7) % lengths.length] : Math.floor(Math.random() * 400));
    assert.equal(hex(C.hmacSha256Bytes([...key], [...msg])), createHmac('sha256', key).update(msg).digest('hex'));
    assert.equal(hex(C.sha256Bytes([...msg])), createHash('sha256').update(msg).digest('hex'));
  }
});

test('HMAC-SHA256: UTF-8 strings, hex and Base64 output match Node', () => {
  const key = 'ключ 🔑', msg = 'héllo wörld 🎉 日本語';
  assert.equal(C.hmacSha256Hex(key, msg), createHmac('sha256', key).update(msg).digest('hex'));
  assert.equal(C.hmacSha256Base64(key, msg), createHmac('sha256', key).update(msg).digest('base64'));
  for (let n = 0; n < 10; n++) {
    const b = randomBytes(n);
    assert.equal(C.toBase64([...b]), b.toString('base64'));
    assert.equal(C.toBase64Url([...b]), b.toString('base64url'));
  }
});

test('JWT HS256: signature verifies with Node, and header/payload decode', () => {
  const header = '{"alg":"HS256","typ":"JWT"}';
  const payload = '{"sub":"0031x00000AbCdE","name":"Zoë","iat":1700000000}';
  const token = C.jwtHS256(header, payload, 'shared-secret');
  const [h, p, sig] = token.split('.');
  assert.equal(Buffer.from(h, 'base64url').toString(), header);
  assert.equal(Buffer.from(p, 'base64url').toString(), payload);
  assert.equal(sig, createHmac('sha256', 'shared-secret').update(`${h}.${p}`).digest('base64url'));
  // jwt.io's well-known example token.
  assert.equal(
    C.jwtHS256(header, '{"sub":"1234567890","name":"John Doe","iat":1516239022}', 'your-256-bit-secret'),
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  );
});
