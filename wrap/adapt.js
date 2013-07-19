
var prvKeyHead = "-----BEGIN RSA PRIVATE KEY-----";
var prvKeyFoot = "-----END RSA PRIVATE KEY-----";
var pubKeyHead = "-----BEGIN PUBLIC KEY-----";
var pubKeyFoot = "-----END PUBLIC KEY-----";

function _rsapem_extractEncodedData2(sPEMKey)
{
    var s = sPEMKey;
    s = s.replace(prvKeyHead, "");
    s = s.replace(prvKeyFoot, "");
    s = s.replace(pubKeyHead, "");
    s = s.replace(pubKeyFoot, "");
    s = s.replace(/[ \n]+/g, "");
    return s;
}

RSAKey.prototype.readPrivateKeyFromPEMString = function (keyPEM)
{
    return this.readPrivateKeyFromPkcs1PemString(_rsapem_extractEncodedData2(keyPEM));
}

RSAKey.prototype.readPublicKeyFromPEMString = function (keyPEM)
{
    return this.readPublicKeyFromX509PEMString(_rsapem_extractEncodedData2(keyPEM));
}
