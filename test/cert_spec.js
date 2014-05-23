/*global describe: false,
         it: false,
         expect: false,
         jsjws: false,
         cert: false */
/*jslint node: true */
"use strict";

describe('X509 certificates', function ()
{
    it('should expose the X509 class', function ()
    {
        expect(typeof jsjws.X509).to.equal('function');
    });

    it('should read a X509 certificate', function ()
    {
        var slow_pub_key = jsjws.X509.getPublicKeyFromCertPEM(cert_pem),
            pem = slow_pub_key.publicKeyToPEMString();

        expect(pem).to.equal(cert_pub_pem);
    });

    it('should verify using key read from X509 certificate', function (cb)
    {
        var priv_key = jsjws.createPrivateKey(cert_priv_pem),
            header = { alg: 'PS256' },
            sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key),
            slow_pub_key = jsjws.X509.getPublicKeyFromCertPEM(cert_pem),
            pub_key = jsjws.createPublicKey(slow_pub_key.publicKeyToPEMString()),
            jws = new jsjws.JWS();

        expect(jws.verifyJWSByKey(sig, pub_key));
        expect(jws.getParsedHeader()).to.eql(header);
        expect(jws.getParsedPayload()).to.eql(payload);

        cb();
    });

    // sign and verify signature
});
