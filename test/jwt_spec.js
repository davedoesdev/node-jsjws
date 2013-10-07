/*global priv_keys: false,
         all_algs: false,
         it: false,
         jsjws: false,
         expect: false,
         payload2: false,
         pub_keys: false,
         describe: false,
         sinon: false,
         before: false,
         after: false */
/*jslint node: true, forin: true */
"use strict";

function generate_parse_jwt(alg, priv_name)
{
    var priv_key = priv_keys[alg][priv_name],
        header = { alg: alg },
        expected_header = Object.create(header),
        keys = Object.keys(payload2);

    expected_header.typ = 'JWT';
    keys.push('exp', 'nbf', 'iat', 'jti');
    keys.sort();

    it('should generate and parse JWT using algorithm=' + alg +
       ', priv_key=' + priv_name, function (cb)
    {
        var check = function (err, sjwt)
        {
            if (err)
            {
                cb(err);
                return;
            }

            var jwt = new jsjws.JWT(), ppayload, x;
            jwt.processJWS(sjwt);

            ppayload = jwt.getParsedPayload();
            expect(Object.keys(ppayload).sort()).to.eql(keys);

            for (x in payload2)
            {
                expect(ppayload[x]).to.equal(payload2[x]);
            }

            expect(jwt.getParsedHeader()).to.eql(expected_header);
            cb();
        },

        expires = new Date();
        expires.setSeconds(expires.getSeconds() + 10);

        check(null, new jsjws.JWT().generateJWTByKey(header, payload2, expires, priv_key));
    });
}

function generate_verify_jwt(alg, priv_name, pub_name, get_clock)
{
    var priv_key = priv_keys[alg][priv_name],
        pub_key = pub_keys[alg][pub_name],
        header = { alg: alg },
        jtis = {},
        keys = Object.keys(payload2),

    setup = function (exp, iat_skew, nbf, keyless, expected)
    {
        var expected_header = Object.create(header);

        expected_header.typ = 'JWT';

        if (keyless)
        {
            expected_header.alg = 'none';
        }

        it('should generate and verify using algorithm=' + alg +
           ', priv_key=' + priv_name + ', pub_key=' + pub_name +
           ', exp=' + exp + ', iat_skew=' + iat_skew +
           ', nbf=' + nbf + ', keyless=' + keyless, function (cb)
        {
            var check = function (err, sjwt)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                var options = {
                    iat_skew: iat_skew
                },

                jwt = new jsjws.JWT(),
                f = function ()
                {
                    return jwt.verifyJWTByKey(sjwt, options, keyless ? null : pub_key);
                },
                f2 = function ()
                {
                    return jwt.verifyJWTByKey(sjwt, options, global.generated_key);
                },
                ppayload, x;

                if (keyless && expected)
                {
                    expect(f2()).to.equal(true);
                }
                else
                {
                    expect(f2).to.throw(Error);
                }

                jwt = new jsjws.JWT();

                if (expected)
                {
                    expect(f()).to.equal(true);
                }
                else
                {
                    expect(f).to.throw(Error);
                }

                if (!expected)
                {
                    cb();
                    return;
                }

                ppayload = jwt.getParsedPayload();

                expect(Object.keys(ppayload).sort()).to.eql(keys.sort());

                for (x in payload2)
                {
                    expect(ppayload[x]).to.equal(payload2[x]);
                }

                expect(typeof(ppayload.jti)).to.equal('string');
                expect(jtis).not.to.contain.keys(ppayload.jti);
                jtis[ppayload.jti] = true;

                expect(jwt.getParsedHeader()).to.eql(expected_header);

                cb();
            },

            expires = new Date(),
            not_before = null,
            sjwt;

            expires.setSeconds(expires.getSeconds() + exp);

            if (nbf)
            {
                not_before = new Date();
                not_before.setMinutes(not_before.getMinutes() + nbf);
            }

            sjwt = new jsjws.JWT().generateJWTByKey(header, payload2, expires, not_before, keyless ? null : priv_key);

            setTimeout(function ()
            {
                check(null, sjwt);
            }, 1500);

            get_clock().tick(1500);
        });
    },
    
    setup2 = function (keyless)
    {
        setup(10, 0, null, keyless, true);
        setup(1, 0, null, keyless, false);

        setup(10, -10, null, keyless, false);
        setup(1, -10, null, keyless, false);

        setup(10, 10, null, keyless, true);
        setup(1, 10, null, keyless, false);


        setup(10, 0, 1, keyless, false);
        setup(1, 0, 1, keyless, false);

        setup(10, -10, 1, keyless, false);
        setup(1, -10, 1, keyless, false);

        setup(10, 10, 1, keyless, false);
        setup(1, 10, 1, keyless, false);


        setup(10, 0, -1, keyless, true);
        setup(1, 0, -1, keyless, false);

        setup(10, -10, -1, keyless, false);
        setup(1, -10, -1, keyless, false);

        setup(10, 10, -1, keyless, true);
        setup(1, 10, -1, keyless, false);
    };

    keys.push('exp', 'nbf', 'iat', 'jti');
    keys.sort();

    setup2(false);
    setup2(true);
}

describe('generate-verify-jwt', function ()
{
    var i, alg, priv_key, pub_key, clock,
        
    get_clock = function ()
    {
        return clock;
    };

    before(function ()
    {
        clock = sinon.useFakeTimers();
    });

    after(function ()
    {
        clock.restore();
    });

    for (i = 0; i < all_algs.length; i += 1)
    {
        alg = all_algs[i];

        for (priv_key in priv_keys[alg])
        {
            generate_parse_jwt(alg, priv_key);

            for (pub_key in pub_keys[alg])
            {
                generate_verify_jwt(alg, priv_key, pub_key, get_clock);
            }
        }
    }
});

