#!/bin/bash
cd "$(dirname "$0")/.."

files=$(echo {jsrsasign/{ext/{rsa,rsa2,base64,jsbn,jsbn2,cryptojs-312-core-fix},asn1hex-1.1,base64x-1.1,crypto-1.1,rsasign-1.2,keyutil-1.0,asn1-1.0,asn1x509-1.0,x509-1.1},js-rsa-pem/rsa-pem,crypto-js/build/components/{x64-core,sha256,sha512,hmac},jsjws/jws-2.0,wrap/adapt}.js)

cat wrap/node.js $files wrap/postlude.js > lib/jsjws.js

loader="test/fixtures/loader.html"

cat > "$loader" <<EOF
<html>
<head>
<title>node-jsjws test loader</title>
<script src="../../node_modules/yui/yui-base/yui-base-debug.js"></script>
<script src="../../node_modules/yui/attribute-core/attribute-core-min.js"></script>
<script src="../../node_modules/yui/attribute-base/attribute-base-min.js"></script>
<script src="../../node_modules/yui/attribute-observable/attribute-observable-min.js"></script>
<script src="../../node_modules/yui/attribute-extras/attribute-extras-min.js"></script>
<script src="../../node_modules/yui/event-custom-base/event-custom-base-min.js"></script>
<script src="../../node_modules/yui/event-custom-complex/event-custom-complex-min.js"></script>
<script src="../../node_modules/yui/pluginhost-base/pluginhost-base-min.js"></script>
<script src="../../node_modules/yui/pluginhost-config/pluginhost-config-min.js"></script>
<script src="../../node_modules/yui/base-core/base-core-min.js"></script>
<script src="../../node_modules/yui/base-observable/base-observable-min.js"></script>
<script src="../../node_modules/yui/base-pluginhost/base-pluginhost-min.js"></script>
<script src="../../node_modules/yui/base-base/base-base-min.js"></script>
<script src="../../node_modules/yui/base-build/base-build-min.js"></script>
<script src="../../node_modules/yui/oop/oop-min.js"></script>
<script>
var YAHOO;
YUI({bootstrap: false}).use('base', function (Y)
{
    YAHOO = Y;
    YAHOO.lang = YAHOO;
});
</script>
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

