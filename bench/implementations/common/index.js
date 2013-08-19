/*global priv_keys: false,
         pub_keys: false,
         jwcrypto: false */
/*jslint node: true */
"use strict";

require('../../../test/_common.js');

global.jwcrypto = require('jwcrypto');
require('jwcrypto/lib/algs/rs');

priv_keys.jwcrypto = jwcrypto.loadSecretKeyFromObject(
{
    algorithm: 'RS',
    n: priv_keys.slow.n.toString(),
    e: priv_keys.slow.e.toString(),
    d: priv_keys.slow.d.toString()
});

pub_keys.jwcrypto = jwcrypto.loadPublicKeyFromObject(
{
    algorithm: 'RS',
    n: pub_keys.slow.n.toString(),
    e: pub_keys.slow.e.toString()
});
