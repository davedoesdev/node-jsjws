#!/bin/bash
set -e
cd "$(dirname "$0")/.."

files=$(echo {jsrsasign/{ext/{rsa,rsa2,base64,jsbn,jsbn2,cj/{cryptojs-312-core-fix,x64-core,sha256,sha512,hmac}},src/{jws-3.3,x509-1.1,rsapem-1.1,asn1hex-1.1,ecdsa-modified-1.0,base64x-1.1,crypto-1.1,keyutil-1.0,rsasign-1.2}},js-rsa-pem/rsa-pem,wrap/adapt}.js)

cat wrap/node.js $files wrap/postlude.js > lib/jsjws.js

loader="test/fixtures/loader.html"

cat > "$loader" <<EOF
<html>
<head>
<title>node-jsjws test loader</title>
<script type="text/javascript">
function SecureRandom() { }

SecureRandom.prototype.nextBytes = function(ba)
{
    var ua = new Uint8Array(ba.length), i;

    window.crypto.getRandomValues(ua);

    for (i = 0; i < ba.length; i += 1)
    {
        ba[i] = ua[i];
    }
};
</script>
EOF

for f in $files jsrsasign/ext/json-sans-eval.js
do

cat >> "$loader" <<EOF
<script type="text/javascript" src="../../$f"></script>
EOF

done

cat >> "$loader" <<EOF
</head>
<body>
</body>
</html>
EOF
