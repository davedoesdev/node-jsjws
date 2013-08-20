/*global it: false,
         describe: false,
         pub_keys: false,
         priv_keys: false,
         pub_pem: false,
         priv_pem: false */
/*jslint node: true, nomen: true */
"use strict";

var generate_verify = require('./generate_verify_spec'),
    child_process = require('child_process'),
    path = require('path'),
    util = require('util');

describe('python-jws-interop', function ()
{
    /*jslint unparam: true */

    this.timeout(60*1000);

    var spawn = function (cmd, json, cb)
    {
        var cp, env = process.env, stdout = '', stderr = '';

        env.PYTHONPATH = __dirname + path.delimiter +
                         path.join(__dirname, '..', 'python-jws');

        cp = child_process.spawn(
                'python',
                ['-c', 'from fixtures import *; ' + cmd],
                { env: env });

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

    generate = function (header, payload, cb)
    {
        spawn(util.format("generate('%j', '%j', '%j')",
                          header, payload, priv_pem),
              false,
              cb);
    },
    
    verify = function (sjws, cb)
    {
        spawn(util.format("verify('%j', '%j')", sjws, pub_pem),
              true,
              cb);
    };

    /*jslint unparam: false */

    pub_keys.python_jws = verify;
    priv_keys.python_jws = generate;
    generate_verify.setup(['RS256', 'RS512', 'PS256', 'PS512']);
    delete pub_keys.python_jws;
    delete priv_keys.python_jws;
});
