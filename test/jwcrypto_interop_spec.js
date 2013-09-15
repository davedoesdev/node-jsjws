/*global it: false,
         describe: false,
         pub_keys: false,
         priv_keys: false */
/*jslint node: true */
"use strict";

var jwcrypto = require('jwcrypto');
require('jwcrypto/lib/algs/rs');

describe('jwcrypto-interop', function ()
{
    /*jslint unparam: true */

    var pub_key = jwcrypto.loadPublicKeyFromObject(
    {
        algorithm: 'RS',
        n: pub_keys.RS256.slow.n.toString(),
        e: pub_keys.RS256.slow.e.toString()
    }),

    priv_key = jwcrypto.loadSecretKeyFromObject(
    {
        algorithm: 'RS',
        n: priv_keys.RS256.slow.n.toString(),
        e: priv_keys.RS256.slow.e.toString(),
        d: priv_keys.RS256.slow.d.toString()
    }),

    generate = function (header, payload, cb)
    {
        jwcrypto.sign(payload, priv_key, function (err, jws)
        {
            if (err)
            {
                cb(err);
                return;
            }

            cb(null, jws);
        });
    },
    
    verify = function (sjws, cb)
    {
        jwcrypto.verify(sjws, pub_key, cb);
    };

    /*jslint unparam: false */

    pub_keys.RS256 = Object.create(pub_keys.RS256);
    pub_keys.RS256.jwcrypto = verify;
    priv_keys.RS256 = Object.create(priv_keys.RS256);
    priv_keys.RS256.jwcrypto = generate;
    require('./generate_verify_spec').setup(['RS256']);
    pub_keys.RS256 = Object.getPrototypeOf(pub_keys.RS256);
    priv_keys.RS256 = Object.getPrototypeOf(priv_keys.RS256);
});
