/*global RSAKey: false,
         KJUR: false,
         jsonParse: false,
         utf8tob64u: true */
/*jslint nomen: true, node: true */
"use strict";

var _prvKeyHead = "-----BEGIN RSA PRIVATE KEY-----";
var _prvKeyFoot = "-----END RSA PRIVATE KEY-----";
var _pubKeyHead = "-----BEGIN PUBLIC KEY-----";
var _pubKeyFoot = "-----END PUBLIC KEY-----";
/*jslint regexp: true */
var _re_pem = /(.{1,64})/g;
/*jslint regexp: false */

function _rsapem_extractEncodedData2(sPEMKey)
{
    var s = sPEMKey;
    s = s.replace(_prvKeyHead, "");
    s = s.replace(_prvKeyFoot, "");
    s = s.replace(_pubKeyHead, "");
    s = s.replace(_pubKeyFoot, "");
    s = s.replace(/[ \n]+/g, "");
    return s;
}

RSAKey.prototype.readPrivateKeyFromPEMString = function (keyPEM)
{
    return this.readPrivateKeyFromPkcs1PemString(_rsapem_extractEncodedData2(keyPEM));
};

RSAKey.prototype.readPublicKeyFromPEMString = function (keyPEM)
{
    return this.readPublicKeyFromX509PEMString(_rsapem_extractEncodedData2(keyPEM));
};

RSAKey.prototype.privateKeyToPEMString = function ()
{
    return _prvKeyHead + '\n' +
           this.privateKeyToPkcs1PemString().replace(_re_pem, '$1\n') +
           _prvKeyFoot + '\n';
};

RSAKey.prototype.publicKeyToPEMString = function ()
{
    return _pubKeyHead + '\n' +
           this.publicKeyToX509PemString().replace(_re_pem, '$1\n') +
           _pubKeyFoot + '\n';
};

KJUR.jws._orig_JWS = KJUR.jws.JWS;

KJUR.jws.JWS = function ()
{
    KJUR.jws._orig_JWS.call(this);

    this._orig_isSafeJSONString = this.isSafeJSONString;

    this.isSafeJSONString = function (s, h, p)
    {
        if (typeof s !== "string")
        {
            if (h)
            {
                h[p] = s;
            }

            return 1;
        }

        return this._orig_isSafeJSONString(s, h, p);
    };
};

KJUR.jws.JWS.prototype.getUnparsedHeader = function ()
{
    return this.parsedJWS && this.parsedJWS.headS;
};

KJUR.jws.JWS.prototype.getUnparsedPayload = function ()
{
    return this.parsedJWS && this.parsedJWS.payloadS;
};

KJUR.jws.JWS.prototype.getParsedHeader = function ()
{
    if (this.parsedJWS)
    {
        if (!this.parsedJWS.headP && this.parsedJWS.headS)
        {
            this.parsedJWS.headP = jsonParse(this.parsedJWS.headS);
        }

        return this.parsedJWS.headP;
    }

    return undefined;
};

KJUR.jws.JWS.prototype.getParsedPayload = function ()
{
    if (this.parsedJWS)
    {
        if (!this.parsedJWS.payloadP && this.parsedJWS.payloadS)
        {
            this.parsedJWS.payloadP = jsonParse(this.parsedJWS.payloadS);
        }

        return this.parsedJWS.payloadP;
    }

    return undefined;
};

KJUR.jws.JWS.prototype.processJWS = function (jws)
{
    this.parseJWS(jws, true);
};

var _orig_utf8tob64u = utf8tob64u;

utf8tob64u = function (s)
{
    return _orig_utf8tob64u(typeof s !== "string" ? JSON.stringify(s) : s);
};
