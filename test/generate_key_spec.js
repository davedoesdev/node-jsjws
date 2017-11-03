/*global it: false,
         expect: false,
         jsjws: false,
         spayload: false,
         describe: false */
/*jslint node: true */
"use strict";

function check_generate_key(alg, type, gen)
{
    var header = JSON.stringify({ alg: alg });

    it('should generate usable keys using algorithm=' + alg +
       ', type=' + type, function ()
    {
        var priv_keys = {}, pub_keys = {}, sigs = {},

        f = function (priv_pem, pub_pem, sjws)
        {
            expect(priv_keys).not.to.contain.keys(priv_pem);
            expect(pub_keys).not.to.contain.keys(pub_pem);
            expect(sigs).not.to.contain.keys(sjws);

            var pub_key, priv_key, jws;

            pub_key = jsjws.createPublicKey(pub_pem);
            jws = new jsjws.JWS();
            expect(jws.verifyJWSByKey(sjws, pub_key, [alg])).to.equal(true);
            expect(jws.getUnparsedPayload()).to.equal(spayload);
            expect(jws.getUnparsedHeader()).to.equal(header);

            pub_key = new jsjws.SlowRSAKey();
            pub_key.readPublicKeyFromPEMString(pub_pem);
            jws = new jsjws.JWS();
            expect(jws.verifyJWSByKey(sjws, pub_key, [alg])).to.equal(true);
            expect(jws.getUnparsedPayload()).to.equal(spayload);
            expect(jws.getUnparsedHeader()).to.equal(header);

            priv_key = new jsjws.createPrivateKey(priv_pem);
            jws = new jsjws.JWS();
            expect(jws.verifyJWSByKey(sjws, priv_key.toPublicKey(), [alg])).to.equal(true);
            expect(jws.getUnparsedPayload()).to.equal(spayload);
            expect(jws.getUnparsedHeader()).to.equal(header);

            priv_key = new jsjws.SlowRSAKey();
            priv_key.readPrivateKeyFromPEMString(priv_pem);
            jws = new jsjws.JWS();
            expect(jws.verifyJWSByKey(sjws, priv_key.toPublicKey(), [alg])).to.equal(true);
            expect(jws.getUnparsedPayload()).to.equal(spayload);
            expect(jws.getUnparsedHeader()).to.equal(header);

            priv_keys[priv_pem] = true;
            pub_keys[pub_pem] = true;
            sigs[sjws] = true;
        };

        gen(header, f);
    });
}

describe('generate_key', function ()
{
    this.timeout(30 * 60 * 1000);

    var algs = ['RS256', 'RS512', 'PS256', 'PS512'], i,
    
    fast = function (header, cb)
    {
        var key = jsjws.generatePrivateKey(2048, 65537);

        cb(key.toPrivatePem(),
           key.toPublicPem(),
           new jsjws.JWS().generateJWSByKey(header, spayload, key));
    },

    slow = function (header, cb)
    {
        var key = new jsjws.SlowRSAKey();
        key.generate(2048, '10001');

        cb(key.privateKeyToPEMString(),
           key.publicKeyToPEMString(),
           new jsjws.JWS().generateJWSByKey(header, spayload, key));
    };

    for (i = 0; i < algs.length; i += 1)
    {
        check_generate_key(algs[i], 'fast', fast);
        check_generate_key(algs[i], 'slow', slow);
    }
});

