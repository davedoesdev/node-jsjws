/*global RSAKey: false,
         KJUR: false,
         X509: false */
/*jslint node: true */

var util = require('util'),
    crypto = require('crypto'),
    keypair = require('keypair');

exports.SlowRSAKey = RSAKey;
exports.JWS = KJUR.jws.JWS;
exports.JWT = KJUR.jws.JWT;
exports.X509 = X509;

function PublicKey(public_pem)
{
    this._public_pem = public_pem;
}

PublicKey.prototype.toPublicPem = function ()
{
    return this._public_pem;
};

PublicKey.prototype.hashAndVerify = function (algorithm,
                                              buf,
                                              sig,
                                              encoding,
                                              use_pss_padding,
                                              salt_len)
{
    var key = { key: this.toPublicPem() };

    if (use_pss_padding)
    {
        key.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        if (salt_len === undefined)
        {
            key.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
        }
        else
        {
            key.saltLength = salt_len;
        }
    }
    else
    {
        key.padding = crypto.constants.RSA_PKCS1_PADDING;
    }

    return crypto.createVerify('RSA-' + algorithm.toUpperCase())
            .update(buf, encoding)
            .verify(key, sig, encoding);

};

function PrivateKey(private_pem, password)
{
    PublicKey.call(this);
    this._private_pem = private_pem;
    this._password = password;
}

util.inherits(PrivateKey, PublicKey);

PrivateKey.prototype.toPrivatePem = function ()
{
    return this._private_pem;
};

PrivateKey.prototype.toPublicPem = function ()
{
    if (!this._public_pem)
    {
        var key = new RSAKey();
        key.readPrivateKeyFromPEMString(this._private_pem);
        this._public_pem = key.publicKeyToPEMString();
    }

    return this._public_pem;
};

PrivateKey.prototype.hashAndSign = function (algorithm,
                                             buf, bufEncoding,
                                             outEncoding,
                                             use_pss_padding, salt_len)
{
    var key = { key: this.toPrivatePem() };

    if (this._password !== undefined)
    {
        key.passphrase = this._password;
    }

    if (use_pss_padding)
    {
        key.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        if (salt_len === undefined)
        {
            key.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
        }
        else
        {
            key.saltLength = salt_len;
        }
    }
    else
    {
        key.padding = crypto.constants.RSA_PKCS1_PADDING;
    }

    return crypto.createSign('RSA-' + algorithm.toUpperCase())
            .update(buf, bufEncoding)
            .sign(key, outEncoding);
};

exports.createPublicKey = function (public_pem)
{
    return new PublicKey(public_pem);
};

exports.createPrivateKey = function (private_pem, password)
{
    return new PrivateKey(private_pem, password);
};

exports.generatePrivateKey = function (modulusBits, exponent)
{
    return new PrivateKey(keypair(
    {
        bits: modulusBits,
        exponent: exponent
    }).private);
};

