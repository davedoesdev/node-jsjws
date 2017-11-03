/*global it: false,
         describe: false,
         pub_keys: false,
         priv_keys: false,
         pub_pem: false,
         priv_pem: false */
/*jslint node: true */
"use strict";

var node_jws = require('jws');

describe('node-jws-interop', function ()
{
    /*jslint unparam: true */

    var generate = function (header, payload, cb)
    {
        cb(null, node_jws.sign(
        {
            header: header,
            payload: payload,
            privateKey: priv_pem
        }));
    },
    
    verify = function (sjws, alg, cb)
    {
        var s = node_jws.createVerify(
        {
            signature: sjws,
            publicKey: pub_pem,
            algorithm: alg
        });

        s.on('done', function (valid, obj)
        {
            if (valid)
            {
                cb(null, JSON.parse(obj.payload));
            }
            else
            {
                cb('failed to verify');
            }
        });
    };

    /*jslint unparam: false */

    pub_keys.RS256 = Object.create(pub_keys.RS256);
    pub_keys.RS256.node_jws = verify;
    priv_keys.RS256 = Object.create(priv_keys.RS256);
    priv_keys.RS256.node_jws = generate;
    require('./generate_verify_spec').setup(['RS256']);
    pub_keys.RS256 = Object.getPrototypeOf(pub_keys.RS256);
    priv_keys.RS256 = Object.getPrototypeOf(priv_keys.RS256);
});
