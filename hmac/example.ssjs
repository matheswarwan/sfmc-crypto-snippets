<script runat="server">
  Platform.Load("core", "1.1.1");

  // Paste the contents of hmac/hmac-sha256.js here (or above this block),
  // so SfmcCrypto is defined before the code below runs.

  // Keep secrets out of the code: read them from a data extension only you can access.
  var secret = Platform.Function.Lookup("Crypto_Settings", "Value", "Name", "webhook_secret");

  // 1. Sign a webhook: the receiver recomputes the HMAC of the raw body and compares.
  var body = Platform.Function.Stringify({ event: "journey_entry", contactKey: "0031x00000AbCdE" });
  var request = new Script.Util.HttpRequest("https://example.com/webhook");
  request.method = "POST";
  request.contentType = "application/json";
  request.setHeader("X-Signature", "sha256=" + SfmcCrypto.hmacSha256Hex(secret, body));
  request.postData = body;
  var response = request.send();

  // 2. Make an HS256 JWT, for example for an API that accepts signed tokens.
  var now = Math.floor(new Date().getTime() / 1000);
  var token = SfmcCrypto.jwtHS256(
    Platform.Function.Stringify({ alg: "HS256", typ: "JWT" }),
    Platform.Function.Stringify({ sub: "0031x00000AbCdE", iat: now, exp: now + 300 }),
    secret
  );
</script>
