/*global RSAKey: false,
         KJUR: false,
         jsonParse: false,
         utf8tob64u: true,
         SecureRandom: false,
         BAtohex: false,
         ASN1HEX: false */
/*jslint nomen: true, node: true, newcap: true, forin: true */
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

function _asnhex_getStartPosOfV_AtObj(s, pos)
{
    return ASN1HEX.getStartPosOfV_AtObj(s, pos);
}

function _asnhex_getPosOfNextSibling_AtObj(s, pos)
{
    return ASN1HEX.getPosOfNextSibling_AtObj(s, pos);
}

function _asnhex_getHexOfV_AtObj(s, pos)
{
    return ASN1HEX.getHexOfV_AtObj(s, pos);
}

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

KJUR.jws.JWT = function ()
{
    KJUR.jws.JWS.apply(this, arguments);
};

KJUR.jws.JWT.prototype = Object.create(KJUR.jws.JWS.prototype);

KJUR.jws.JWT.prototype.generateJWTByKey = function (header, claims, expires, not_before, key)
{
    if (key === undefined)
    {
        key = not_before;
        not_before = null;
    }

    var new_header = {}, new_claims = {}, x, jti = new Array(128), now;

    for (x in header)
    {
        new_header[x] = header[x];
    }

    if (!key)
    {
        new_header.alg = 'none';
    }

    new_header.typ = 'JWT';

    for (x in claims)
    {
        new_claims[x] = claims[x];
    }

    new SecureRandom().nextBytes(jti);

    now = new Date();
    
    not_before = not_before || now;

    new_claims.jti = BAtohex(jti);
    new_claims.iat = Math.floor(now.getTime() / 1000);
    new_claims.nbf = Math.floor(not_before.getTime() / 1000);
    new_claims.exp = Math.floor(expires.getTime() / 1000);

    return this.generateJWSByKey(new_header, new_claims, key);
};

KJUR.jws.JWT.prototype.verifyJWTByKey = function (jwt, options, key)
{
    if (key === undefined)
    {
        key = options;
        options = null;
    }

    if (key)
    {
        this.verifyJWSByKey(jwt, key);
    }
    else
    {
        this.processJWS(jwt);
    }

    options = options || {};

    var header = this.getParsedHeader(),
        claims = this.getParsedPayload(),
        now = Math.floor(new Date().getTime() / 1000),
        iat_skew = options.iat_skew || 0;

    if (!header)
    {
        throw new Error('no header');
    }

    if (!claims)
    {
        throw new Error('no claims');
    }

    if (header.typ !== 'JWT')
    {
        throw new Error('type is not JWT');
    }

    if (claims.iat === undefined)
    {
        throw new Error('no issued at claim');
    }

    if (claims.iat > (now + iat_skew))
    {
        throw new Error('issued in the future');
    }

    if (claims.nbf === undefined)
    {
        throw new Error('no not before claim');
    }

    if (claims.nbf > now)
    {
        throw new Error('not yet valid');
    }

    if (claims.exp === undefined)
    {
        throw new Error("no expires claim");
    }

    if (claims.exp <= now)
    {
        throw new Error("expired");
    }

    return true;
};
