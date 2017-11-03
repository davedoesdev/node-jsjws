/*global expect: false,
         it: false,
         describe: false,
         jsjws: false,
         all_algs: false,
         payload: false,
         priv_keys: false,
         pub_keys: false */
/*jslint node: true */
"use strict";

var all_algs2 = all_algs.concat(['none']);

function check_allowed(alg, privk, pubk)
{
    it('should fail to verify token generated with alg ' + alg + ', allowed algorithms not specified', function ()
    {
        var expires = new Date(), token, jwt;
        expires.setSeconds(expires.getSeconds() + 60);
        token = new jsjws.JWT().generateJWTByKey({ alg: alg }, payload, expires, privk);
        jwt = new jsjws.JWT();
        expect(function ()
        {
            jwt.verifyJWTByKey(token, pubk);
        }).to.throw("algorithm not allowed: " + alg);
    });

    it('should verify token generated with alg ' + alg + ', all algorithms allowed', function ()
    {
        var expires = new Date(), token, jwt;
        expires.setSeconds(expires.getSeconds() + 60);
        token = new jsjws.JWT().generateJWTByKey({ alg: alg }, payload, expires, privk);
        jwt = new jsjws.JWT();
        expect(jwt.verifyJWTByKey(token, pubk, all_algs2)).to.equal(true);
    });

    it('should fail to verify token generated with alg ' + alg + ', no algorithms allowed', function ()
    {
        var expires = new Date(), token, jwt;
        expires.setSeconds(expires.getSeconds() + 60);
        token = new jsjws.JWT().generateJWTByKey({ alg: alg }, payload, expires, privk);
        jwt = new jsjws.JWT();
        expect(function ()
        {
            jwt.verifyJWTByKey(token, pubk, []);
        }).to.throw("algorithm not allowed: " + alg);
    });

    it('should fail to verify token generated with alg ' + alg + ', algorithm not allowed', function ()
    {
        var expires = new Date(), token, jwt;
        expires.setSeconds(expires.getSeconds() + 60);
        token = new jsjws.JWT().generateJWTByKey({ alg: alg }, payload, expires, privk);
        jwt = new jsjws.JWT();
        expect(function ()
        {
            jwt.verifyJWTByKey(token, pubk, all_algs2.filter(function (a)
            {
                return a !== alg;
            }));
        }).to.throw("algorithm not allowed: " + alg);
    });
}

describe('allowed-algs', function ()
{
    var i, alg;
    check_allowed('none', null, null);
    for (i = 0; i < all_algs.length; i += 1)
    {
        alg = all_algs[i];
        check_allowed(alg,
                      priv_keys[alg].default || priv_keys[alg].fast,
                      pub_keys[alg].default || pub_keys[alg].fast);
    }
});
