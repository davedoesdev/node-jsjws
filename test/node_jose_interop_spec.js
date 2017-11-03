/*global priv_pem, pub_pem, pub_keys, priv_keys */
/*jshint node: true, esversion: 6, mocha: true */
"use strict";

const jose = require('node-jose');

describe('node-jose-interop', function ()
{
    function generate(header, payload, cb)
    {
        jose.JWK.asKey(priv_pem, 'pem').
        then(function (key)
        {
            jose.JWS.createSign(Object.assign(
            {
                format: 'compact'
            }, header),
            {
                key: key,
                reference: false
            }).
            final(JSON.stringify(payload)).
            then(function (sig)
            {
                cb(null, sig);
            });
        });
    }

    function verify(sjws, alg, cb)
    {
        jose.JWK.asKey(pub_pem, 'pem').
        then(function (key)
        {
            jose.JWS.createVerify(key).
            verify(sjws).
            then(function (r)
            {
                cb(null, JSON.parse(r.payload));
            });
        }).
        catch(cb);
    }

    pub_keys.RS256 = Object.create(pub_keys.RS256);
    pub_keys.RS256.node_jws = verify;
    priv_keys.RS256 = Object.create(priv_keys.RS256);
    priv_keys.RS256.node_jws = generate;
    require('./generate_verify_spec').setup(['RS256']);
    pub_keys.RS256 = Object.getPrototypeOf(pub_keys.RS256);
    priv_keys.RS256 = Object.getPrototypeOf(priv_keys.RS256);
});
