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

RSAKey.prototype.toPublicKey = function ()
{
    var key = new RSAKey();
    key.readPublicKeyFromPEMString(this.publicKeyToPEMString());
    return key;
};

function _asnhex_getStartPosOfV_AtObj(s, pos)
{
    return ASN1HEX.getVidx(s, pos);
}

function _asnhex_getPosOfNextSibling_AtObj(s, pos)
{
    return ASN1HEX.getNextSiblingIdx(s, pos);
}

function _asnhex_getHexOfV_AtObj(s, pos)
{
    return ASN1HEX.getV(s, pos);
}

KJUR.jws.JWS.prototype.generateJWSByKey = function (sHead, sPayload, key, password)
{
    if (typeof key === 'string')
    {
        key = { rstr: key };
    }

    return KJUR.jws.JWS.sign(null, sHead, sPayload, key, password);
};

KJUR.jws.JWS.prototype.verifyJWSByKey = function (sJWS, key, allowed_algs)
{
    if (typeof key === 'string')
    {
        key = { rstr: key };
    }

    allowed_algs = allowed_algs || [];

    if (!Array.isArray(allowed_algs))
    {
        throw new Error('allowed_algs must be an array');
    }

    this.parseJWS(sJWS[sJWS.length - 1] === '.' ? (sJWS + 'X') : sJWS);

    var alg = this.parsedJWS.headP.alg;

    if (allowed_algs.indexOf(alg) === -1)
    {
        throw new Error('algorithm not allowed: ' + alg);
    }

    var r = false;
    try
    {
        r = KJUR.jws.JWS.verify(sJWS, key, allowed_algs);
    }
    catch (ex)
    {
        if ((ex === 'not supported') && (alg === 'none'))
        {
            return true;
        }

        if ((ex === 'key shall be specified to verify.') &&
            (allowed_algs.indexOf('none') >= 0))
        {
            return true;
        }

        throw typeof ex === 'string' ? new Error(ex) : ex;
    }

    if (!r)
    {
        throw new Error('failed to verify');
    }

    return r;
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

KJUR.jws.JWS.prototype.getUnparsedHeader = function ()
{
    return this.parsedJWS && this.parsedJWS.headS;
};

KJUR.jws.JWS.prototype.getUnparsedPayload = function ()
{
    return this.parsedJWS && this.parsedJWS.payloadS;
};

KJUR.jws.JWS.prototype.processJWS = function (jws)
{
    this.parseJWS(jws, true);
};

KJUR.jws.JWT = function ()
{
    KJUR.jws.JWS.apply(this, arguments);
};

KJUR.jws.JWT.prototype = Object.create(KJUR.jws.JWS.prototype);

KJUR.jws.JWT.prototype.generateJWTByKey = function (header, claims, expires, not_before, jti_size, key, password)
{
    if (not_before && !(not_before instanceof Date))
    {
        password = key;
        key = jti_size;
        jti_size = not_before;
        not_before = null;
    }

    if (jti_size && (typeof jti_size !== 'number'))
    {
        password = key;
        key = jti_size;
        jti_size = 16;
    }

    var new_header = {}, new_claims = {}, x, jti, now;
    
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

    now = new Date();
    
    not_before = not_before || now;

    if (jti_size)
    {
        jti = [];
        jti.length = jti_size;
        new SecureRandom().nextBytes(jti);
        new_claims.jti = BAtohex(jti);
    }

    new_claims.iat = Math.floor(now.getTime() / 1000);
    new_claims.nbf = Math.floor(not_before.getTime() / 1000);

    if (expires)
    {
        new_claims.exp = Math.floor(expires.getTime() / 1000);
    }

    return this.generateJWSByKey(new_header, new_claims, key, password);
};

KJUR.jws.JWT.prototype.verifyJWTByKey = function (jwt, options, key, allowed_algs)
{
    if (allowed_algs === undefined)
    {
        allowed_algs = key;
        key = options;
        options = null;
    }

    this.verifyJWSByKey(jwt, key, allowed_algs);

    options = options || {};

    function bool_or_obj(name)
    {
        var v = options[name];
        return typeof(v) === 'boolean' ?
        {
            typ: v,
            iat: v,
            nbf: v,
            exp: v
        } : (v || {});
    }

    var header = this.getParsedHeader(),
        claims = this.getParsedPayload(),
        now = Math.floor(new Date().getTime() / 1000),
        iat_skew = options.iat_skew || 0,
        checks_optional = bool_or_obj('checks_optional'),
        skip_checks = bool_or_obj('skip_checks');

    if (!header)
    {
        throw new Error('no header');
    }

    if (!claims)
    {
        throw new Error('no claims');
    }

    if (!skip_checks.typ)
    {
        if (header.typ === undefined)
        {
            if (!checks_optional.typ)
            {
                throw new Error('no type claim');
            }
        }
        else if (header.typ !== 'JWT')
        {
            throw new Error('type is not JWT');
        }
    }

    if (!skip_checks.iat)
    {
        if (claims.iat === undefined)
        {
            if (!checks_optional.iat)
            {
                throw new Error('no issued at claim');
            }
        }
        else if (claims.iat > (now + iat_skew))
        {
            throw new Error('issued in the future');
        }
    }

    if (!skip_checks.nbf)
    {
        if (claims.nbf === undefined)
        {
            if (!checks_optional.nbf)
            {
                throw new Error('no not before claim');
            }
        }
        else if (claims.nbf > now)
        {
            throw new Error('not yet valid');
        }
    }

    if (!skip_checks.exp)
    {
        if (claims.exp === undefined)
        {
            if (!checks_optional.exp)
            {
                throw new Error("no expires claim");
            }
        }
        else if (claims.exp <= now)
        {
            throw new Error("expired");
        }
    }

    return true;
};
