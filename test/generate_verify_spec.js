/*global priv_keys: false,
         all_algs: false,
         it: false,
         jsjws: false,
         expect: false,
         payload: false,
         pub_keys: false,
         describe: false */
/*jslint node: true, forin: true */
"use strict";

function generate_parse(alg, priv_name)
{
    var priv_key = priv_keys[alg][priv_name],
        header = { alg: alg },

    setup = function (f, type)
    {
        it('should generate and parse using algorithm=' + alg +
           ', priv_key=' + priv_name + ', type=' + type, function (cb)
        {
            var check = function (err, sjws)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                var jws = new jsjws.JWS();
                jws.processJWS(sjws);
                expect(jws.getParsedPayload()).to.eql(payload);
                expect(jws.getParsedHeader()).to.eql(header);
                cb();
            };

            if (typeof priv_key === 'function')
            {
                priv_key(header, payload, check);
            }
            else
            {
                check(null, new jsjws.JWS().generateJWSByKey(f(header), f(payload), priv_key));
            }
        });
    };

    setup(function (x) { return x; }, 'object');

    if (typeof priv_key !== 'function')
    {
        setup(function (x) { return JSON.stringify(x); }, 'string');
    }
}

function generate_verify(alg, priv_name, pub_name)
{
    var priv_key = priv_keys[alg][priv_name],
        pub_key = pub_keys[alg][pub_name],
        header = { alg: alg },

    setup = function (f, type)
    {
        it('should generate and verify using algorithm=' + alg +
           ', priv_key=' + priv_name + ', pub_key=' + pub_name +
           ', type=' + type, function (cb)
        {
            var check = function (err, sjws)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                var jws = new jsjws.JWS();
                expect(function ()
                {
                    jws.verifyJWSByKey(sjws, global.generated_key, [alg]);
                }).to.throw(Error);

                if (typeof pub_key === 'function')
                {
                    pub_key(sjws, function (err, payload)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        expect(payload).to.eql(global.payload);
                        cb();
                    });
                }
                else
                {
                    jws = new jsjws.JWS();
                    expect(jws.verifyJWSByKey(sjws, pub_key, [alg])).to.equal(true);
                    expect(jws.getParsedPayload()).to.eql(payload);
                    expect(jws.getParsedHeader()).to.eql(header);
                    cb();
                }
            };

            if (typeof priv_key === 'function')
            {
                priv_key(header, payload, check);
            }
            else
            {
                check(null, new jsjws.JWS().generateJWSByKey(f(header), f(payload), priv_key));
            }
        });
    };

    setup(function (x) { return x; }, 'object');

    if (typeof priv_key !== 'function')
    {
        setup(function (x) { return JSON.stringify(x); }, 'string');
    }
}

function setup_generate_verify(algs)
{
    algs = algs || all_algs;

    var i, alg, priv_key, pub_key;

    for (i = 0; i < algs.length; i += 1)
    {
        alg = algs[i];

        for (priv_key in priv_keys[alg])
        {
            generate_parse(alg, priv_key);

            for (pub_key in pub_keys[alg])
            {
                generate_verify(alg, priv_key, pub_key);
            }
        }
    }
}

exports.setup = setup_generate_verify;

if (require('path').basename(module.parent.filename) === 'mocha.js')
{
    describe('generate-verify', setup_generate_verify);
}
