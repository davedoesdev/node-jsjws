/*global it: false,
         describe: false,
         pub_keys: false,
         priv_keys: false,
         all_algs: false,
         pub_pem: false,
         priv_pem: false */
/*jslint node: true, nomen: true */
"use strict";

var child_process = require('child_process'),
    which = require('which'),
    util = require('util');

describe('python-jwcrypto-interop', function ()
{
    /*jslint unparam: true */

    var spawn = function (cmd, json, cb)
    {
        var stdout = '', stderr = '',

        cp = child_process.spawn(
                which.sync('python'), // work around bug under nyc where 
                                      // child_process.spawn doesn't seem to
                                      // search PATH and raises ENOENT
                ['-c', 'from fixtures import *; ' + cmd],
                { env: { PYTHONPATH: __dirname }});

        cp.stdout.on('data', function (data)
        {
            stdout += data;
        });

        cp.stderr.on('data', function (data)
        {
            stderr += data;
        });

        cp.on('close', function (code, signal)
        {
            if (code === 0)
            {
                cb(null, json ? JSON.parse(stdout) : stdout);
            }
            else
            {
                cb(new Error(stderr || ('exited with ' + (code || signal))));
            }
        });

        cp.on('err', cb);
    },

    generate = function (alg)
    {
        return function (header, payload, cb)
        {
            spawn(util.format("generate('%j', '%j', '%j')",
                              header,
                              payload,
                              priv_keys[alg].default || priv_pem),
                  false,
                  cb);
        };
    },
    
    verify = function (sjws, alg, cb)
    {
        spawn(util.format("verify('%j', '%j')",
                          sjws,
                          pub_keys[alg].default || pub_pem),
              true,
              cb);
    },

    i, alg;

    /*jslint unparam: false */

    for (i = 0; i < all_algs.length; i += 1)
    {
        alg = all_algs[i];
        pub_keys[alg] = Object.create(pub_keys[alg]);
        pub_keys[alg].python_jwcrypto = verify;
        priv_keys[alg] = Object.create(priv_keys[alg]);
        priv_keys[alg].python_jwcrypto = generate(alg);
    }
    
    require('./generate_verify_spec').setup();

    for (i = 0; i < all_algs.length; i += 1)
    {
        alg = all_algs[i];
        pub_keys[alg] = Object.getPrototypeOf(pub_keys[alg]);
        priv_keys[alg] = Object.getPrototypeOf(priv_keys[alg]);
    }
});
