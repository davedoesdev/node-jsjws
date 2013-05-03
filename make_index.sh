#!/bin/bash
cd "$(dirname "$0")"
cat node.js {jsjws/{jsbn,jsbn2,base64,base64x-1.1,sha512,rsa,rsa2,rsasign-1.2,asn1hex-1.0,jws-1.1},js-rsa-pem/rsa-pem}.js adapt.js > index.js
cat >> index.js <<EOF
exports.RSAKey = RSAKey;
exports.JWS = JWS;
EOF
