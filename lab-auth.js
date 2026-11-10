/*
 * LAB ONLY - authenticated chat for Dynamics 365 Contact Center.
 * In production the token is created and signed on the website's SERVER.
 * Here it is signed in the browser so the lab needs no server.
 * Never put a private key in a web page in real life.
 */

// ---- 1. Fill in: the GUID of Jan Peeters' contact record ----
var LAB_CONTACT_ID = "f0ebe792-3dd4-f111-84e8-7ced8d95b46e";
var LAB_ISSUER = "contosobank-lab";

// Lab private key (PKCS#8, base64). Matches public_key.pem.
var LAB_PRIVATE_KEY_B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzB6EPEdthY710wFa54mXPKdPDvbaPSkVBgMvMfSD//NwOqfamimIYVmWZvdRrp/wVf1X1iw5iv71KVfXDm40RK9HnIhy+jcgZBEDdzxLgX1RhujGgnml5mYvBhqR6m2ARuMSG5ILAjkqRIWTwOnLGCDm1vVcZUp2irMET+8lddjLeV2IU/O33b6IOoVvm9Cl87KdJTo8NPZBL7cS6Igc3nf+He/7WEd/SRzzmGGsX58Vn1JasibsRMsL7HggLTuNHfnWOpighBtonUMpOVHtBRXZtX5c29b6HJYbSsiiIgIrTuNJPeWM0Rc9Ad90N7+4f18PkFqfoOLjXvRHun4LxAgMBAAECggEAK7Fe8O0mcmtyp9deoDvGTwj3lBT7Cebx7ZVgzopekPdeftpqyEVP3o1F5e6djp9ccGb8xtDxzKopN4Cd10WThpdIvRPCdDXcWDcODHLKs4EgFBPcEUL5to129VumHY7qpjUATDowEbtjR5Vn5tKzSMw4x+ZbDufuBE2nxtZ5PO6F/iZiGsdaNKvkOjD+8Ilq1RFJxhoE0QRpiJeLpyqOJx5qONQyB+djU8WgwnmQYVSGi++DtOv4LvzxU74hurN4DIiJMGF3JOV04CxjrWhdn1+Pf55XnOfY5erJZB/9GnUf74ieYu7DjhpDPthwJM0rlFpUe6tRejupHvSlhngsKwKBgQD/y3cR5w65LDkKscObWH5mu1ydJDKkKWxJBdnlsyZelqsSQIabEROb/YavPi4EWaWsnJP0h1CMtApxjaUWjHuMPWeg2v+MrTwzMbHomfVCpN2kCqb1qe7b7kETNl4oeGS/GzRIvtg/PanvMds4HE/7Oc7ccbJC15bp9hX9gn7xlwKBgQDzOYrYDrLb3/4+fzkL+H3V0m5geun9h/B3dB2fEZ/zz8qKIYZE8oj6EydKF9jIpeHkSooiGRAuAZ5KIldEUqksTVU0Y8+jbd5oODKbkuO2arCcSsJ36pLugkJyhrZVEk8Vw282wwAkhS+y+I4LPam3vvXisxE7IWcEhfKMpZ+wtwKBgF3vVyug4XxI7C2sODwdFFYfqhQfDeXRPG3YkztSPd3wkKQkRApADCZ1xPcn63g3f6rS2VasNn1lRIyMyrpsHpbSmfKtWblMiNX4AvB7UWEG8Enki4mdvRTQ+t7WUV+lTsILeHjadMlMmNI5SdriMtD8WqYDrsXzK/2BHHQ7bujDAoGAHCOGGqTosGNjqJtTYD0pYblsp6DQvVIi0c8PNj31wWFCz2Q9gnCExFm+6+WCYQQ/9Adjn7pCkvAA/ham/fKKO+PefacmeIPXfTszL6h4y7vgHtTPVsw+n3VWdqV7JrBtkdkAXteEhrUZ5Zy34jkKD4X6MHYDAlJE9tMAUqE+rlUCgYEA/CRIxOXvlND4V8g9PfWw4xjNBLZIGbdKKZZ4zNO+qnn5LAr2O/9S0MXZeuBQO/rdYG3aMZOPhyM5j4HxPr0nhaIS/t2urwkVjxFtq79WwCgNrXzirJAlvW+TGdjdYwGyLrqehvBG+DAm0UdiY5jo6jYQsvx1EkGG710oPGGCZrA=";

// ---- 2. Test modes, chosen with the page URL: livechat.html?mode=valid ----
//   valid    : correct, signed token for LAB_CONTACT_ID
//   tampered : valid token, then the "sub" is swapped WITHOUT re-signing
//   expired  : correctly signed, but "exp" lies one hour in the past
//   none     : the function returns no token at all
//   &tier=Private adds lwicontexts {"CustomerTier":"Private"}
var params = new URLSearchParams(window.location.search);
var LAB_MODE = params.get("mode") || "valid";
var LAB_TIER = params.get("tier");

function b64url(bytes) {
  var s = "";
  var arr = new Uint8Array(bytes);
  for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function labSign(payload) {
  var der = Uint8Array.from(atob(LAB_PRIVATE_KEY_B64), function (c) { return c.charCodeAt(0); });
  var key = await crypto.subtle.importKey("pkcs8", der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  var input = b64urlJson({ alg: "RS256", typ: "JWT" }) + "." + b64urlJson(payload);
  var sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input));
  return input + "." + b64url(sig);
}

async function labCreateToken() {
  var now = Math.floor(Date.now() / 1000);
  var payload = { sub: LAB_CONTACT_ID, iss: LAB_ISSUER, iat: now, exp: now + 3600 };
  if (LAB_MODE === "expired") { payload.iat = now - 7200; payload.exp = now - 3600; }
  if (LAB_TIER) payload.lwicontexts = JSON.stringify({ CustomerTier: LAB_TIER });

  var token = await labSign(payload);

  if (LAB_MODE === "tampered") {
    // Change the claimed identity after signing: the signature no longer matches.
    var parts = token.split(".");
    var forged = Object.assign({}, payload, { sub: "00000000-0000-0000-0000-000000000001" });
    token = parts[0] + "." + b64urlJson(forged) + "." + parts[2];
  }
  return token;
}

// ---- 3. The function Dynamics calls. Name to enter in the admin center: auth.getAuthenticationToken
window.auth = window.auth || {};
window.auth.getAuthenticationToken = function (callback) {
  console.log("[lab-auth] Dynamics asked for a token. Mode:", LAB_MODE, "Tier:", LAB_TIER);
  if (LAB_MODE === "none") { callback(null); return; }
  labCreateToken().then(function (token) {
    console.log("[lab-auth] Token handed to the chat widget:", token);
    callback(token);
  }).catch(function (err) {
    console.error("[lab-auth] Could not create token", err);
    callback(null);
  });
};
