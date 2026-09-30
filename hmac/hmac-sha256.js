/*
  SHA-256, HMAC-SHA256 and HS256 JWTs for Marketing Cloud server-side
  JavaScript (SSJS). AMPscript and SSJS have hash functions but no HMAC, so
  this is plain ES3 JavaScript, which is what SSJS runs.

  It defines one global, SfmcCrypto. With key "Jefe" and message
  "what do ya want for nothing?" (RFC 4231 test case 2):
    SfmcCrypto.hmacSha256Hex(key, message)     -> "5bdcc146bf60754e..."
    SfmcCrypto.hmacSha256Base64(key, message)  -> "W9zBRr9gdU5qBCQm..."
    SfmcCrypto.sha256Hex(message)
    SfmcCrypto.jwtHS256(headerJson, payloadJson, secret)
  Strings are encoded as UTF-8 before hashing.
*/
var SfmcCrypto = (function () {
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  function utf8Bytes(text) {
    var s = unescape(encodeURIComponent(String(text)));
    var bytes = [];
    for (var i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
    return bytes;
  }

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var msg = bytes.slice(0);
    var bitLength = bytes.length * 8;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    // Message length as a 64-bit big-endian number. The high 32 bits.
    var high = Math.floor(bitLength / 4294967296);
    msg.push((high >>> 24) & 255, (high >>> 16) & 255, (high >>> 8) & 255, high & 255);
    msg.push((bitLength >>> 24) & 255, (bitLength >>> 16) & 255, (bitLength >>> 8) & 255, bitLength & 255);

    var w = [];
    for (var offset = 0; offset < msg.length; offset += 64) {
      for (var t = 0; t < 16; t++) {
        var j = offset + t * 4;
        w[t] = (msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (k + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) | 0;
        k = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
    }
    var out = [];
    for (var i = 0; i < 8; i++) out.push((h[i] >>> 24) & 255, (h[i] >>> 16) & 255, (h[i] >>> 8) & 255, h[i] & 255);
    return out;
  }

  // RFC 2104. Keys longer than the 64-byte block are hashed first.
  function hmacSha256(keyBytes, messageBytes) {
    var key = keyBytes.length > 64 ? sha256(keyBytes) : keyBytes.slice(0);
    while (key.length < 64) key.push(0);
    var inner = [], outer = [];
    for (var i = 0; i < 64; i++) {
      inner.push(key[i] ^ 0x36);
      outer.push(key[i] ^ 0x5c);
    }
    return sha256(outer.concat(sha256(inner.concat(messageBytes))));
  }

  function toHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return hex;
  }

  function toBase64(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | ((i + 1 < bytes.length ? bytes[i + 1] : 0) << 8) | (i + 2 < bytes.length ? bytes[i + 2] : 0);
      out += B64.charAt((n >>> 18) & 63) + B64.charAt((n >>> 12) & 63);
      out += i + 1 < bytes.length ? B64.charAt((n >>> 6) & 63) : "=";
      out += i + 2 < bytes.length ? B64.charAt(n & 63) : "=";
    }
    return out;
  }

  function toBase64Url(bytes) {
    return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  return {
    utf8Bytes: utf8Bytes,
    sha256Hex: function (message) {
      return toHex(sha256(utf8Bytes(message)));
    },
    hmacSha256Hex: function (key, message) {
      return toHex(hmacSha256(utf8Bytes(key), utf8Bytes(message)));
    },
    hmacSha256Base64: function (key, message) {
      return toBase64(hmacSha256(utf8Bytes(key), utf8Bytes(message)));
    },
    // For keys given as hex (for example a secret shared as hex bytes).
    hmacSha256HexKey: function (hexKey, message) {
      var key = [];
      for (var i = 0; i < hexKey.length; i += 2) key.push(parseInt(hexKey.substr(i, 2), 16));
      return toHex(hmacSha256(key, utf8Bytes(message)));
    },
    // headerJson and payloadJson are JSON strings, for example from
    // Platform.Function.Stringify({ alg: "HS256", typ: "JWT" }).
    jwtHS256: function (headerJson, payloadJson, secret) {
      var input = toBase64Url(utf8Bytes(headerJson)) + "." + toBase64Url(utf8Bytes(payloadJson));
      return input + "." + toBase64Url(hmacSha256(utf8Bytes(secret), utf8Bytes(input)));
    },
    // Byte arrays (numbers 0 to 255) in and out, for binary keys and data.
    sha256Bytes: sha256,
    hmacSha256Bytes: hmacSha256,
    toHex: toHex,
    toBase64: toBase64,
    toBase64Url: toBase64Url
  };
})();
