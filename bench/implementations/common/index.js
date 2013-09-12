/*global priv_keys: false,
         pub_keys: false,
         jwcrypto: false */
/*jslint node: true */
"use strict";

require('../../../test/_common.js');

global.jwcrypto = require('jwcrypto');
require('jwcrypto/lib/algs/rs');

priv_keys.RS256.jwcrypto = jwcrypto.loadSecretKeyFromObject(
{
    algorithm: 'RS',
    n: priv_keys.RS256.slow.n.toString(),
    e: priv_keys.RS256.slow.e.toString(),
    d: priv_keys.RS256.slow.d.toString()
});

pub_keys.RS256.jwcrypto = jwcrypto.loadPublicKeyFromObject(
{
    algorithm: 'RS',
    n: pub_keys.RS256.slow.n.toString(),
    e: pub_keys.RS256.slow.e.toString()
});
