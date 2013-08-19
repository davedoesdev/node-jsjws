/*global jwcrypto: false,
         payload: false,
         priv_keys: false,
         pub_keys: false,
         jsjws: false */

/*jslint node: true, unparam: true */
"use strict";

require('./common');

module.exports = {
    genkey: function (b, e, done)
    {
        jwcrypto.generateKeypair(
        {
            algorithm: 'RS',
            keysize: 256
        }, done);
    },

    generate: function (alg, done)
    {
        jwcrypto.sign(payload, priv_keys.jwcrypto, done);
    },

    verify: function (sig, done)
    {
        jwcrypto.verify(sig, pub_keys.jwcrypto, done);
    },

    loadkey: function (pem, done)
    {
        var key = new jsjws.SlowRSAKey();
        key.readPrivateKeyFromPEMString(pem);
        done(null, jwcrypto.loadSecretKeyFromObject(
        {
            algorithm: 'RS',
            n: key.n.toString(),
            e: key.e.toString(),
            d: key.d.toString()
        }));
    }
};

