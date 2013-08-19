/*global it: false,
         jsjws: false,
         spayload: false,
         priv_keys: false,
         expect: false,
         describe: false */
/*jslint node: true, forin: true */
"use strict";

function check_same(alg, priv_key)
{
    var header = JSON.stringify({ alg: alg });

    it('should generate identical signatures using algorithm=' + alg +
       ', priv_key=' + priv_key, function ()
    {
        var i, sjws = new jsjws.JWS().generateJWSByKey(header, spayload, priv_keys[priv_key]);

        for (i = 0; i < 5; i += 1)
        {
            expect(new jsjws.JWS().generateJWSByKey(header, spayload, priv_keys[priv_key])).to.equal(sjws);
        }
    });
}

function check_different(alg, priv_key)
{
    var header = JSON.stringify({ alg: alg });

    it('should generate different signatures using algorithm=' + alg +
       ', priv_key=' + priv_key, function ()
    {
        var i, sigs = {}, sjws;
        
        for (i = 0; i < 5; i += 1)
        {
            sjws = new jsjws.JWS().generateJWSByKey(header, spayload, priv_keys[priv_key]);
            expect(sigs).not.to.contain.keys(sjws);
            sigs[sjws] = true;
        }

        expect(Object.keys(sigs).length).to.equal(5);
    });
}

describe('variance', function ()
{
    var algs = ['RS256', 'RS512'], i, priv_key;

    for (i = 0; i < algs.length; i += 1)
    {
        for (priv_key in priv_keys)
        {
            check_same(algs[i], priv_key);
        }
    }

    algs = ['PS256', 'PS512'];

    for (i = 0; i < algs.length; i += 1)
    {
        for (priv_key in priv_keys)
        {
            check_different(algs[i], priv_key);
        }
    }
});

