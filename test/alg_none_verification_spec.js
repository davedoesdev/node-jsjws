/*global expect: false,
         it: false,
         describe: false,
         jsjws: false */
/*jslint node: true */
"use strict";

var jwt_alg_none = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpYXQiOjAsIm5iZiI6MCwiZXhwIjoxZTIwfQ.";

describe('alg-none-verification', function ()
{
    it('should verify the token when public key not specified and none alg is allowed', function ()
    {
        var jwt = new jsjws.JWT();
        expect(jwt.verifyJWTByKey(jwt_alg_none, null, ['none'])).to.equal(true);
    });

    it('should verify the token when a public key is specified and none alg is allowed', function ()
    {
        var jwt = new jsjws.JWT();
        expect(jwt.verifyJWTByKey(jwt_alg_none, 'anysecrethere', ['none'])).to.equal(true);
    });

    it('should fail to verify the token when a public key is specified', function ()
    {
        var jwt = new jsjws.JWT();
        expect(function ()
        {
            jwt.verifyJWTByKey(jwt_alg_none, 'anysecrethere');
        }).to.throw('algorithm not allowed: none');
    });
});

