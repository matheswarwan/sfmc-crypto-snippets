# sfmc-crypto-snippets

Two small, tested crypto helpers for Salesforce Marketing Cloud (SFMC):

- **AES that interoperates with AMPscript.** Values encrypted with `EncryptSymmetric(…, "aes", …)` can be decrypted in Node, and Node can produce values that `DecryptSymmetric` reads.
- **HMAC-SHA256, SHA-256 and HS256 JWTs in server-side JavaScript (SSJS).** AMPscript and SSJS have hash functions but no HMAC. These are needed for signing webhooks or creating JWTs, so this repo implements them in plain ES3 JavaScript, which is what SSJS runs.

## AES: Node ↔ AMPscript

Marketing Cloud's `aes` works like this:
1. It derives a 256-bit key from the password and salt with PBKDF2 (HMAC-SHA1, 1000 iterations).
2. It encrypts with AES-256-CBC and PKCS#7 padding.

The salt (8 bytes) and IV (16 bytes) are given as hex. The ciphertext is Base64.

```js
import { encrypt, decrypt, randomSaltAndIv } from './aes/sfmc-aes.mjs';

const options = { password: process.env.AES_PASSWORD, ...randomSaltAndIv() }; // or your fixed salt and IV
const cipher = encrypt('0031x00000AbCdE', options);
decrypt(cipher, options); // '0031x00000AbCdE'
```

```
%%[ set @plain = DecryptSymmetric(@cipher, "aes", @null, @password, @null, @salt, @null, @iv) ]%%
```

Use the same password, salt and IV on both sides. [`aes/examples.ampscript`](aes/examples.ampscript) shows both directions, with the settings read from a data extension rather than typed into content. The 3rd, 5th and 7th arguments of `EncryptSymmetric`/`DecryptSymmetric` take Key Management key IDs instead of literal values, if you prefer to keep them there.

A Base64 ciphertext can contain `+`, `/` and `=`. If you put it in a URL, URL-encode it: an unencoded `+` arrives as a space.

## HMAC-SHA256 and JWTs in SSJS

[`hmac/hmac-sha256.js`](hmac/hmac-sha256.js) defines one global, `SfmcCrypto`:

| Function | Returns |
|---|---|
| `hmacSha256Hex(key, message)` | HMAC as lowercase hex |
| `hmacSha256Base64(key, message)` | HMAC as Base64 |
| `hmacSha256HexKey(hexKey, message)` | HMAC with a key given as hex bytes |
| `sha256Hex(message)` | SHA-256 as hex |
| `jwtHS256(headerJson, payloadJson, secret)` | A signed JWT (`header.payload.signature`) |
| `sha256Bytes`, `hmacSha256Bytes`, `toHex`, `toBase64`, `toBase64Url`, `utf8Bytes` | Lower-level helpers on byte arrays |

Strings are encoded as UTF-8 before hashing, which matches what most other platforms do.

To use it, paste the file's contents into your CloudPage, code resource or Script Activity, inside `<script runat="server">`, before the code that calls it. [`hmac/example.ssjs`](hmac/example.ssjs) signs a webhook with `Script.Util.HttpRequest` and builds a short-lived JWT.

## Tests

```sh
npm install
npm test
```

- **AES** reproduces a public Marketing Cloud example in both directions. The example is from [this Salesforce StackExchange question](https://salesforce.stackexchange.com/q/384953): a ciphertext that `DecryptSymmetric` decrypted, with its password, salt and IV.
- **SHA-256 and HMAC** are checked against:
  - the FIPS 180 and RFC 4231 test vectors;
  - Node's `crypto` on 500 random keys and messages, including lengths around the 64-byte block boundary;
  - UTF-8 text.
- **The JWT function** reproduces jwt.io's example token.
- **The SSJS file** is parsed as strict ES3 (with `acorn`), so it uses nothing SSJS lacks, such as `let`, arrow functions, `JSON` or trailing commas.

## Limitations

- **Not run in a live account:** the tests run in Node. The AES scheme is confirmed by the StackExchange example. The SSJS code only uses ES3 features that SSJS supports, but it hasn't been run inside a Marketing Cloud account yet.
- **SSJS speed:** SSJS is slow, and hashing is pure JavaScript. Signing a few kilobytes per request is fine; hashing megabytes is not.
- **Security basics:** keep passwords, salts, IVs and secrets out of content and code. A fixed IV makes AES output repeatable (the same input gives the same ciphertext). That's often what you want for lookups in links, but it reveals when two values are equal.

## License

MIT
