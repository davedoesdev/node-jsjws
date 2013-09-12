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
        done(null, jsjws.generatePrivateKey(b, e));
    },

    generate: function (alg, done)
    {
        done(null, new jsjws.JWS().generateJWSByKey({ alg: alg }, payload, priv_keys.RS256.fast));
    },

    verify: function (sig, done)
    {
        done(null, new jsjws.JWS().verifyJWSByKey(sig, pub_keys.RS256.fast));
    },

    loadkey: function (pem, done)
    {
        done(null, jsjws.createPrivateKey(pem, 'utf8'));
    }
};
