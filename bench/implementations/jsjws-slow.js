/*global jsjws: false,
         payload: false,
         priv_keys: false,
         pub_keys: false */
/*jslint node: true */
"use strict";

require('./common');

module.exports = {
    genkey: function (b, e, done)
    {
        var key = new jsjws.SlowRSAKey();
        key.generate(b, e.toString(16));
        done(null, key);
    },

    generate: function (alg, done)
    {
        done(null, new jsjws.JWS().generateJWSByKey({ alg: alg }, payload, priv_keys.RS256.slow));
    },

    verify: function (alg, sig, done)
    {
        done(null, new jsjws.JWS().verifyJWSByKey(sig, pub_keys.RS256.slow, [alg]));
    },

    loadkey: function (pem, done)
    {
        var key = new jsjws.SlowRSAKey();
        key.readPrivateKeyFromPEMString(pem);
        done(null, key);
    }
};
