/*global it: false,
         describe: false,
         pub_keys: false,
         priv_keys: false */
/*jslint node: true */
"use strict";

var jwcrypto = require('jwcrypto');
require('jwcrypto/lib/algs/rs');

var generate_verify = require('./generate_verify_spec');

describe('jwcrypto-interop', function ()
{
    /*jslint unparam: true */

    var pub_key = jwcrypto.loadPublicKeyFromObject(
    {
        algorithm: 'RS',
        n: pub_keys.slow.n.toString(),
        e: pub_keys.slow.e.toString()
    }),

    priv_key = jwcrypto.loadSecretKeyFromObject(
    {
        algorithm: 'RS',
        n: priv_keys.slow.n.toString(),
        e: priv_keys.slow.e.toString(),
        d: priv_keys.slow.d.toString()
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

    pub_keys.jwcrypto = verify;
    priv_keys.jwcrypto = generate;
    generate_verify.setup(['RS256']);
    delete pub_keys.jwcrypto;
    delete priv_keys.jwcrypto;
});
