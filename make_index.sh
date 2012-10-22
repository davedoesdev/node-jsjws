#!/bin/bash
cd "$(dirname "$0")"
cat > index.js <<EOF
var navigator = {
  appName: "Netscape"
};
function alert(s)
{
  throw new Error(s);
}
var jsonParse = JSON.parse;
EOF
cat {jsjws/{jsbn,jsbn2,base64,base64x-1.1,sha512,rsa,rsa2,rsasign-1.2,asn1hex-1.0,jws-1.1},js-rsa-pem/rsa-pem}.js >> index.js
cat >> index.js <<EOF
exports.RSAKey = RSAKey;
exports.JWS = JWS;
EOF
