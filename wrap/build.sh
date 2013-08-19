#!/bin/bash
cd "$(dirname "$0")/.."

files=$(echo {jsrsasign/{ext/{rsa,rsa2,base64,jsbn,jsbn2},asn1hex-1.1,base64x-1.1,crypto-1.1,rsasign-1.2},js-rsa-pem/rsa-pem,crypto-js/build/components/{core,x64-core,sha256,sha512},jsjws/jws-2.0}.js wrap/adapt.js)

cat wrap/node.js $files wrap/postlude.js > lib/jsjws.js

loader="test/fixtures/loader.html"

cat > "$loader" <<EOF
<html>
<head>
<title>node-jsjws test loader</title>
EOF

for f in $files jsjws/ext/json-sans-eval.js
do

cat >> "$loader" <<EOF
<script type="text/javascript" src="../../$f"></script>
EOF

done

cat >> "$loader" <<EOF
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
</head>
<body>
</body>
</html>
EOF

