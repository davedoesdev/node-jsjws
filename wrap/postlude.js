/*global RSAKey: false,
         KJUR: false,
         X509: false */
/*jshint node: true, esversion: 6 */

var util = require('util'),
    crypto = require('crypto'),
    keypair = require('keypair');

exports.SlowRSAKey = RSAKey;
exports.JWS = KJUR.jws.JWS;
exports.JWT = KJUR.jws.JWT;
exports.X509 = X509;

function PublicKey(public_pem)
{
    RSAKey.call(this);
    this._public_pem = public_pem;
}

util.inherits(PublicKey, RSAKey);

PublicKey.prototype.toPublicPem = function ()
{
    return this._public_pem;
};

function PrivateKey(private_pem)
{
    PublicKey.call(this);
    this._private_pem = private_pem;
}

util.inherits(PrivateKey, PublicKey);

PrivateKey.prototype.toPrivatePem = function (import_password,
                                              export_password,
                                              export_alg)
{
    if ((export_password !== null) && (export_password !== undefined))
    {
        switch (export_alg)
        {
            case 'des':
                export_alg = 'DES-CBC';
                break;

            case 'des3':
                export_alg = 'DES-EDE3-CBC';
                break;

            case 'aes128':
                export_alg = 'AES-128-CBC';
                break;

            case 'aes192':
                export_alg = 'AES-192-CBC';
                break;

            case 'aes256':
                export_alg = 'AES-256-CBC';
                break;

            default:
                throw new Error('unknown encryption algorithm: ' + export_alg);
        }
    }

    if (((import_password !== null) && (import_password !== undefined)) ||
        ((export_password !== null) && (export_password !== undefined)))
    {
        var key = KEYUTIL.getKey(this._private_pem, import_password);
        return KEYUTIL.getPEM(
            key,
            ((export_password === null) || (export_password === undefined)) ?
                'PKCS1PRV' :
                'PKCS5PRV',
            export_password,
            export_alg);
    }

    return this._private_pem;
};

PrivateKey.prototype.toPublicPem = function (password)
{
    if (!this._public_pem)
    {
        var key = KEYUTIL.getKey(this._private_pem, password);
        this._public_pem = key.publicKeyToPEMString();
    }

    return this._public_pem;
};

PrivateKey.prototype.toPublicKey = function (password)
{
    return new PublicKey(this.toPublicPem(password));
};

exports.createPublicKey = function (public_pem)
{
    return new PublicKey(public_pem);
};

exports.createPrivateKey = function (private_pem)
{
    return new PrivateKey(private_pem);
};

try
{
    var turbokey = require('bindings')('turbokey.node');

    exports.generatePrivateKey = function (modulusBits, exponent)
    {
        return new PrivateKey(turbokey.generatePrivateKey(modulusBits, exponent));
    };
}
catch (e)
{
    console.error(e.message);
    console.error('Falling back to slow path (keypair)');

    exports.generatePrivateKey = function (modulusBits, exponent)
    {
        return new PrivateKey(keypair(
        {
            bits: modulusBits,
            exponent: exponent
        }).private);
    };
}

let orig_Mac = KJUR.crypto.Mac;

KJUR.crypto.Mac = function (params)
{
    if (!params.alg.startsWith('Hmac'))
    {
        return orig_mac.apply(this, arguments);
    }

    let key = params.pass;
    if (!Buffer.isBuffer(key))
    {
        key = Buffer.from(key.rstr, 'binary');
    }

    let mac = crypto.createHmac(params.alg.substr(4), key);

    this.updateString = function (s)
    {
        mac.update(Buffer.from(s, 'binary'));
    };

    this.doFinal = function ()
    {
        return mac.digest('hex');
    };
};

let sigalg2jwsalg = new Map();
for (const jwsalg in KJUR.jws.JWS.jwsalg2sigalg)
{
    sigalg2jwsalg[KJUR.jws.JWS.jwsalg2sigalg[jwsalg]] = jwsalg;
}

let orig_Signature = KJUR.crypto.Signature;

KJUR.crypto.Signature = function (params)
{
    let alg = sigalg2jwsalg[params.alg];
    if (!(alg.startsWith('RS') || alg.startsWith('PS')))
    {
        return orig_Signature.apply(this, arguments);
    }

    this.init = function (key, pass)
    {
        let k = {}, obj;

        if (key instanceof PrivateKey)
        {
            k.key = key.toPrivatePem();
            obj = crypto.createSign('RSA-SHA' + alg.substr(2));
        }
        else if (key instanceof PublicKey)
        {
            k.key = key.toPublicPem();
            obj = crypto.createVerify('RSA-SHA' + alg.substr(2));
        }
        else
        {
            let sig = new orig_Signature(params);
            this.updateString = sig.updateString.bind(sig);
            this.sign = sig.sign.bind(sig);
            this.verify = sig.verify.bind(sig);
            return sig.init(key, pass);
        }

        if (alg.startsWith('PS'))
        {
            k.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
            k.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
        }
        else
        {
            k.padding = crypto.constants.RSA_PKCS1_PADDING;
        }

        if (pass !== undefined)
        {
            k.passphrase = pass;
        }

        this.updateString = function (s)
        {
            obj.update(s, 'binary');
        };

        this.sign = function ()
        {
            return obj.sign(k, 'hex');
        };

        this.verify = function (sig)
        {
            return obj.verify(k, sig, 'hex');
        };
    };
};

CryptoJS.PBKDF2 = function (password, salt, cfg)
{
    return CryptoJS.enc.Latin1.parse(
        crypto.pbkdf2Sync(
            password,
            Buffer.from(salt.toString(CryptoJS.enc.Latin1), 'latin1'),
            cfg.iterations,
            cfg.keySize * 4,
            cfg.hasher || 'sha1')
        .toString('latin1'));
};

function decrypt(alg, ciphertext, key, cfg)
{
    let cipher = crypto.createDecipheriv(
        alg,
        Buffer.from(key.toString(CryptoJS.enc.Latin1), 'latin1'),
        Buffer.from(cfg.iv.toString(CryptoJS.enc.Latin1), 'latin1'));

    return CryptoJS.enc.Latin1.parse(
        cipher.update(
            Buffer.from(ciphertext.ciphertext.toString(CryptoJS.enc.Latin1),
                        'latin1'),
            null,
            'latin1') +
        cipher.final('latin1'));
}

function encrypt(alg, data, key, cfg)
{
    let cipher = crypto.createCipheriv(
        alg,
        Buffer.from(key.toString(CryptoJS.enc.Latin1), 'latin1'),
        Buffer.from(cfg.iv.toString(CryptoJS.enc.Latin1), 'latin1'));

    return CryptoJS.enc.Latin1.parse(
        cipher.update(
            Buffer.from(data.toString(CryptoJS.enc.Latin1), 'latin1'),
            null,
            'latin1') +
        cipher.final('latin1'));
}

CryptoJS.AES = {
    decrypt: function (ciphertext, key, cfg)
    {
        return decrypt('AES-' + (key.sigBytes * 8) + '-CBC',
                       ciphertext,
                       key,
                       cfg);
    },

    encrypt: function (data, key, cfg)
    {
        return encrypt('AES-' + (key.sigBytes * 8) + '-CBC',
                       data,
                       key,
                       cfg);
    }
};

CryptoJS.TripleDES = {
    decrypt: function (ciphertext, key, cfg)
    {
        return decrypt('DES3', ciphertext, key, cfg);
    },

    encrypt: function (data, key, cfg)
    {
        return encrypt('DES3', data, key, cfg);
    }
};


CryptoJS.DES = {
    decrypt: function (ciphertext, key, cfg)
    {
        return decrypt('DES', ciphertext, key, cfg);
    },

    encrypt: function (data, key, cfg)
    {
        return encrypt('DES', data, key, cfg);
    }
};
