/*global expect: false,
         it: false,
         describe: false,
         pub_pem: false,
         jsjws: false,
         before: false,
         payload: false,
         pub_keys: false */
/*jslint node: true */
"use strict";

describe('pem-as-hmac-key', function ()
{
    var token;

    before(function ()
    {
        // generate HS256 token using public PEM string as key
        var expires = new Date();
        expires.setSeconds(expires.getSeconds() + 60);
        token = new jsjws.JWT().generateJWTByKey({ alg: 'HS256' }, payload, expires, pub_pem);
    });

    it('should verify token using public PEM string as public key when no allowed algorithm is specified', function ()
    {
        // verify token using public PEM string as public key
        new jsjws.JWT().verifyJWTByKey(token, pub_pem);
    });

    it('should fail to verify token using public PEM string as public key when allowed algorithm is specified', function ()
    {
        // specify expected algorithm this time
        expect(function ()
        {
            new jsjws.JWT().verifyJWTByKey(token,
            {
                allowed_algs: ['RS256']
            }, pub_pem);
        }).to.throw('algorithm not allowed: HS256');
    });

    it('should fail to verify token using public key', function ()
    {
        expect(function ()
        {
            new jsjws.JWT().verifyJWTByKey(token, pub_keys.RS256.fast);
        }).to.throw();

        expect(function ()
        {
            new jsjws.JWT().verifyJWTByKey(token, pub_keys.RS256.slow);
        }).to.throw();
    });
});

