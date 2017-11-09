/*jshint node: true, esversion: 6, mocha: true */
let expect = require('chai').expect;
let jsjws = require('..');

// PKCS#8 DES3
// openssl genrsa 2048 | openssl pkcs8 -topk8 -v2 des3
let des3_enc_priv_pem = "" +
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIYILbyNmzLoQCAggA\n" +
"MBQGCCqGSIb3DQMHBAi966Pd+iARqASCBMh8mYcJyMSlqu3SRsPzWt70abXjBHKX\n" +
"ZwE9jFeudrVQOYpUaFH1PiJ+g3NZbphTmg24N+0f2OWuexKO0yx2yUhWvBfIsrrS\n" +
"dFvpUJGNoqgi5SulPt6jwbq+LEKURNqjQaJbO0l5o98zRuDwyotFSqdAfksoG3kC\n" +
"vAoe/rgApM+2pQzN2R/BhaW6hrHoZAA0Mfau7TW+uY+jhOZBIyrlizJPOq3Zdoty\n" +
"B5RGZUQmQqSIj5z+gfsoOOkoGCxEdWLIhSCvf+Y24zppeOil+PgyVSNaLw5jBBix\n" +
"ag0dng4dyzp7DeaC2e+rLpYyq1X8ZeaBTr0RX/+go6DIBYP6VlQCGQLKSFxEWiZv\n" +
"85TcbTKXXjA4fybVX0s67+baHa3FLOfJl2qdRnR3ZlXF6vEyxhLMllU0WkCp3+Ou\n" +
"MBRn9SBnk26jJ2aPfl4VN6VFKO7e+o7wb8iQkxIfsULEA4qGyDBaIyVSRIChbcSe\n" +
"5su1YS496j5PBRIy47R2s140Zl+U8UsA9RO04UPNy9q3ms7KajDBhEGBKb9CVaAX\n" +
"bIovFGS2dGjNL1v2psY2Ovl25/sVm6AZDuHznJGIjfJizFjC81nDuDedKm6hUgys\n" +
"mHlt5qSMHuQeliU7oEt0eZCYWOqHCxZ6mtjjKKu5ifjlw6n9nKml6eJGAFE4psBq\n" +
"xA40NSMAybaTUlX6XUYypfGpAqQrSHl2S0oskNI3ht3kmD6A0o1gdoLEIAQMH41C\n" +
"1lARYGK6mCBpXLBF/VVS7VAx1arS12iHYnS+/ax8tjWFd+ufm59EKZgersOY7Vws\n" +
"hBU0kTGU8Bc68yOuWH8TC24Blrv3PXIccblYJ6lmEzepY7NcZfmGsPVWZzLy1OZV\n" +
"7Uc7YP0z8fCtkVM1MJi0JaTU/3H7oXX4mvTKXXBA/3E660XDfMTUsp9XYucjpBCz\n" +
"hvyYXJYPi/9tK0leJLGabQJAMVdFM6FnvphHRi99KLigz9AEdHDhrgRbZwLtjfzp\n" +
"4sKYj2vXt5vTywohIygRUYwOHpUSV7THU3X5TJHlnhRDMngzB/q4v6g9u/5YBlwi\n" +
"6xhFS5/BdyX7xS/5sziTlHXOnfeGvLsj3DWkXtgDP+5FePWSZvh5hCdJ3Z4J1Tjj\n" +
"ISUwae7RFIXwzl41U/+wkHuLbXK8xTMwn3Smd1RVmqXMN0mMt8PXlZxDQ2Uk+kAf\n" +
"1dPkyn4p4UbW+vPEPAuXL6IJviQiw9WMBkOfZmsLhlULpWEIlES1hRwqArwZqbe6\n" +
"fpLYlQiIf0b0mHj1jQ8hUwyZO6nVkHIGNd6AgRpnz2O8aU8Hre9AULif1Jk0PC5C\n" +
"AYc+4DRkhKCqEEGCT8LMAgcFqZ4nClZXBu1kcgNxUkeJQm11kQYh3+ZvdwjbehOf\n" +
"sJIzw8jNM5jSxigP7ip6raF+6Uh0HJM0lJrj+08wPnMWxX2awf5K5ZvKnvuzqTvU\n" +
"KO81uG0lQLbes0D9jS0rx9zPNFN8nO8XOOUTjR5HEn5dTLsGlSfWEGLE90DzMPkE\n" +
"oQo3YtZOrsETIBQAxi93+YaJoasV7jKQHr/jQn8QSUazwNRMRZuN/GdZM6JOQu6U\n" +
"hhEdV5VqCEdJgogmLJTELLe//+v4DZPTT+rCZj14gy5G3YbgmsfpVtoY9+yHWt5I\n" +
"ul8=\n" +
"-----END ENCRYPTED PRIVATE KEY-----\n";
let des3_enc_priv_pass = "some passwd";

// PKCS#5 DES
// openssl genrsa -des 2048
let des_enc_priv_pem = "" +
"-----BEGIN RSA PRIVATE KEY-----\n" +
"Proc-Type: 4,ENCRYPTED\n" +
"DEK-Info: DES-CBC,ACA6454C198B0AF7\n" +
"\n" +
"GWVimPFcHbgO9pJOuhtrX8Ciojy5rUWJ9ra+0P/Awfz8x7gOmY4j/YtW2IqMYwd8\n" +
"xKtl8i0oEJD32d+VKO0ygNopDFuInnqxYox1A83VgA9rKZomRNayJUqZ798zAYdj\n" +
"NxJlTE7CKdT+jEV6zTvuhT8CaV/np77SCGczYmrAHEXNk4V5ksq4JLJKXRX3AsxO\n" +
"fUuAdKrJ+sSZgpplI/rHARIo8WDwMrSSxyny6dePnZYkFfdiF/Hc3CNQqXsDdwgM\n" +
"XVLHx+34DxHjO77AzTM7wuZnXArlOQDOmL/cp42sCMNDRZ8s6t6xoh/aL/7CDo7s\n" +
"fhK9rDncfJ/3I9tWYd+w3rfHq6czaC2ylEgCev39cVrYK7A8o4zLgkbgiEzLaICG\n" +
"pvU+OkeT/SmYzY+BWtQo15X7zL+M9SJzimtw2tOk5hahlOoAZkaXmXa1eECpgIhX\n" +
"XcXIo7P5OeLpti902xPexjt/moJkecAXC5TkvDVouB9r1nVoaiTEOZNdLpbcNyuO\n" +
"MS5etQmkKWr3SCP0eRAhyo+ojh4YrpGuKFIaOLbfGjlB88p77HBmDMBKKlg0TtUJ\n" +
"AoyKdCEbEn8p4wwhWGnoFh5ueptznUTgGNSbjziC/E5raLnlH/pZt4+snqWGMvYr\n" +
"WfY13+LgVJS7tX7REoBBllmM1njPv6wvij9kRHjg24efCa446qd897Vq80ofIQAE\n" +
"i1Vwahay77jrv5tIFFJTrlJ3TGrdluTswLpHAAvJOXfN4P4vxaZ++8178y58LRYu\n" +
"ezckaWXEHTBZlXf7eNFTAw1SkjJTzOQMACE+y5NjDL4emhRPME5HEbnMIrrQF73C\n" +
"c2tBdsbCCgcy/FVkXPxqYARmdDJOy1CbOQN7mCDak9BJrRZAM+dpJaCi1/Af2y/W\n" +
"2ADb+OqPkl/+snUEFIZrXhU0cF1XkdJ8BU8adL1tYE7QkbfTJACQj/sa0AuXLzRu\n" +
"PSJtiQj5ks0vajW9l9FtQgBsigAEwImq9IaHIKXp/wHcuP2czA/CIREBxxfRDt8m\n" +
"XLPJJMH5fLF2KsquL6Z/NTq8BPuaFhejEkTJMJklKHKJoqnWqXPue8Lam+XVXdPm\n" +
"66ZltP6BZ6CYtipXg1aF0j4yqZd1oESlr24sa8ZtIffVwrmT5xovbAHwWEwE0F9n\n" +
"dSKct2nYVoxcwcNYhWdpxcffUmnIyCzjTCwbiq1cuakwadz8DlxsYITM4SlL/718\n" +
"qfg4A++YDcc9u3SJrO9DCbSFwh7DZrZtvdYYbU55vsckl7Eorihy4PB2p18zyrzW\n" +
"QgrC8tr/Rk81lICilskhYspYjzmKmpZhUqeR7I4q0BVhytP1r57r+L+IKef2DePG\n" +
"A9z6SLU7Cdh2cGLC2hcRrC9R36Om5LdReZKbuibbVVw1BiPgzfhH1+wMBMyaRiNd\n" +
"dhe1Im07uDKnT12jaBr9FlQqQCK7Iiant2owMKHTXRoYa04H+WXIECPHk+hlRE8L\n" +
"pV2UmM+89KsvtL5KFrCQ6c56T9SXZ3mZXGGJ9pR/DUTw98tEivcb615zP4A+N3WS\n" +
"LgJ4VhkWkzUm5Jq6ZNfMpwapuioCuDVB2MLkFXf/6qYum04xqpsj+W7e1CJAikp2\n" +
"-----END RSA PRIVATE KEY-----\n";
let des_enc_priv_pass = "some passwd";

// PKCS#5 AES
// openssl genrsa -aes128 2048
let aes_enc_priv_pem = "" +
"-----BEGIN RSA PRIVATE KEY-----\n" +
"Proc-Type: 4,ENCRYPTED\n" +
"DEK-Info: AES-128-CBC,8232F03E46FFD2600BA63898F7B0E4C9\n" +
"\n" +
"RtE4lgEu3fLMfhUTDnCcv60LiX39kjC2ucPZMqQzAog4IXSbXIJE5UBByhwgmR2R\n" +
"1DBXrYWCbjLPDMCvnlr0gjVJ4lnb1O2KPwLPsWEyzcAoYzSAFq2w/Hf6lg2n26Vj\n" +
"FlAc58s7CfLG5bRwDfn/NUwkSqEMS6shbsDTJPbTcec+FxRDsjZ3ZkXYLwIU9FML\n" +
"zt8OZinvZ0qGykfcaIz+fCzIN8yGhtxdW659m1TK0r9Wp28PBEcckELdjcG+NUur\n" +
"iYi3o/WhC6dmm0Z5mIKIPqbACgEeqRjeVldKgU9MnemPbpaNJ1dGraX6AZhEHxPd\n" +
"OiR12+naDmjDOBHI5E+WTNKBql4OModnDQi8SPf3uXgINHkXc14CXP7Yvl2x9LU6\n" +
"an99Eo0+zVeZGdOrfpJvd9XMHDScCfnCv7zxAaRwv/J5tMWb6nELYM+mTcKJ9zHW\n" +
"d9YIt2cVbbW7TebWsIw/oMtu4g/esdupQn9vcYq8Sv+yh+xGAI5jeTgiQMKuMmnL\n" +
"hqpX9jPZK373lLs1Srq1tPF+k+RN4bZa7xYeIOrXY+X6c9QPamDmKz2io/jbKcl8\n" +
"t0a+6hKo5PceOCZRwKEmJ3B07qEup4EHlVNIpPNn+iE5YopZPKKipDSD87xMv9GA\n" +
"XK1eJ1AuMjWWzpDppXvfkSSnq92M3UqJWCwb4MVl9SGV/8HXnfBNtSzNlCFjN8MR\n" +
"gcIk0O2Hmvg9duCiwhyGSd6Mp+qylzmRtHpQH8YTpiROZjWaUOmvywUdtsIN7+Bs\n" +
"3+b+kgfXQLxvJTtQiOwr3NAWSZEipEQ2gS8IO3GWxTGGy9zXdu8QZE1jzWeALmk9\n" +
"dpr0rSWscJeCkxioEBk8F+LrehfTEWxzQL9sJx3vngljAXcTPYLuKQCYeryqiFKT\n" +
"x5Y8JqX1S7NPsZQdB+oB88PNlIfUsKtPYgu8m2NrnQ/YByCNdQwhtmI/KhFXMp5i\n" +
"Mroz+v9n8pA1bjH5KPG/hzs0djSe77JY+wcHnIx8/u82DS0Fix+PvlOHWvoT7Yg+\n" +
"Z5MvWcAB+kIrAsYRMheapC2uy0Gf6fjxuogK5kM8kc2BuYQnYjMCVZPL54FkW86P\n" +
"LsaseJJG2Yfi9js/3FFS9cxWMzaxkCL1U9fvEL9qfKg0EZ0/zsxHe31/sntfCGqs\n" +
"Llrg9BGqonibUzZglGXVs8uLXlmy43XPuUZUX/4ug7HU+dJtwwDH4wdOKo9nBJ/+\n" +
"S5rpM9rI5VXDshy0TZZbii8xQ9j+qV49ObOdk3LxhDsAwjhtY4w1YoYKoKyTNNxq\n" +
"r0KEifJuZNfRzxiSbxfRLlBoRdkorufImKwHHgWcfZMwMqkaVK/GiZ9HrfrbJXMd\n" +
"G+TvEvDHtVnLYbHhswAcXJ7Xppg8iUd74qJvjwwVbiBnF7OkfxJ6F+t2J0v4viX0\n" +
"ZitOQooqvmyXWLdddjdxE2ZXeCMNeytZxERmVzdCuofJBZ960vXj44hSGnrJbs8a\n" +
"FO8cY6QScKGlf1wtnNw6wPrWdh/SxnrFLLtcr4hKSliohL0GHC/UVRCVBL7Hhe4N\n" +
"JJn/5KP1L21LUf6ahedL2EX54YkBEC51IDcf/Z55eF6gn9haTrp4to3DJzP7EvnC\n" +
"-----END RSA PRIVATE KEY-----\n";
let aes_enc_priv_pass = "my secret password";

// PKCS5#5 unencrypted
// openssl genrsa 2048
let no_enc_priv_pem = "" +
"-----BEGIN RSA PRIVATE KEY-----\n" +
"MIIEowIBAAKCAQEAv2kRjTCsv97FP533uBAbVC8MwvEZLSlQQsvn94uZwdiJN4qB\n" +
"pev0jaV8+Cp5hsD9C0XnN1q5hBDKzldCeAg6A/AcJgN9irsz3x01VmEnmCPaVV1G\n" +
"LbPgKkkOhGMOEa2IaWVmmLJPL4SHhJPN8gp+BLx1P1NdQzLMzUpr+rX7AgVKAuwZ\n" +
"6xvhFrRpirvkB7txs+l62cG2PK7/SjOk+/4dqOgDTrVV/QyVf+z44lf0hp1zMJ3R\n" +
"OXhCQ2FF4NkXmProXJ62hSsmwaWasYifwBLHmV5rzy5ruSxWVbrvJT3aIP+Bwbgv\n" +
"UHbhsIhh8fMsymL4Up/+N1Y4Re3KKdER4kBEVwIDAQABAoIBABc0XJ1aPkcQcacx\n" +
"tltJEJcXERv88IlqDcHbSGbZNK2sW44xK2B7B224lzrao1rzwHmCYvJx/DWHd56m\n" +
"M3erv6TEkhUFrU2JPlOZDeNH6e3mwsxAf4aA3PcjXjAsdgMsn3Hvig2O6Eyha3Bm\n" +
"HrxuCzL1yd0AdTj1SqDEmeyN7T0kQ0MmxoKO/2724W/IfEjMtm37vayOCrx+6s6y\n" +
"84Ks8skXWy29iybiRjUI7yTjr1cMePQTqrnT5QDCDqfOEIonHtoh8TN5I41WTLCw\n" +
"rTWdCopqRdatADVzrW16HrSwznVucjEscxllYm3ZArbaQGxI6bu3UDHlHK08yKDX\n" +
"biB9CUkCgYEA6SorT+fvIIjxWWvbYiuU/ueVxrDnm6KuvZtiy9+tWd0jn0I8wyT6\n" +
"OGqaNWiSsQUhOi9GMadatYw8F4VwVgoIxlhIKHnD5OAPUjaSyyMZ1Ccoyi/rMxev\n" +
"A3uN0suB9GFpFrxjRlL5PJQq2Au0SXrXmoVfLb75ng1RZ33tqtb3WtUCgYEA0igM\n" +
"jYWXV1oJSwALIlifPVH58hRuw79K3zGs2ZLgO39lx5wwHGJJ0FyoPdOT1Bekwd1U\n" +
"spDGPBu9KBxL15+ExdrwqN8m+X8O86xw0sRnTgGRrhfv9uqi1VgtTFWgFeEym5+F\n" +
"8UauuVaj0/Lo6XrfHAyyI+rNfPwmAgTZm7JZIHsCgYEAsVU1I8zOffwpM01oyT1E\n" +
"UKppq3gYbrJIHET12wD/ov0hfpquA+03sXjCWCR0jNXN86bIyDL0Nme1vF3slkOD\n" +
"cPbrynzxlD0k6e4/rue/WS9/Qmc3huBYZ1ms/8lvySHc/0HAb1fj30MBYtdkAw6+\n" +
"s/MD9JLu3lpas09/VxOvhRECgYAP7KT23FaZceMeYcR2N8zpMpsD8vRptMcRnowA\n" +
"eJaxK3gk5frnS7NYLI07EhsziQ8c+Y5/cWT0DQ4KSgqdLiM7ctmlkjM72Jrjb/+k\n" +
"mOlTCd9mF75BMYphLCtSi3Jz9fqFvFLD850twhjr6I4pkvvw/i1Jd3NWsyyWHpP2\n" +
"rk7+nQKBgG3PkRGA1zB2VF/nKruwHDq6OFBLKL923zXo8KpkpWwPN82CYP1p8cJH\n" +
"XApQMdx4weeQ2fEI7I+tyshAo3rMu1E/MPdN5MZt9Ui1pNIMaWezlQHl/rbv4TDy\n" +
"11Ocss+3bD+GShh/7Cd5heI0TIFp2Z/F+PnJ1x3dcKXt6hhvLXUF\n" +
"-----END RSA PRIVATE KEY-----\n";
let no_env_priv_pass = null;

function encrypted_key(type, alg, enc_priv_pem, pass)
{

describe('encrypted key (type=' + type + ', alg=' + alg + ')', function ()
{
    it('should be able to sign and verify using encrypted key', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem),
            header = { alg: alg },
            payload = { foo: 'bar', wup: 90 },
            sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key, pass),
            jws = new jsjws.JWS();

        jws.verifyJWSByKey(sig, priv_key.toPublicKey(pass), [alg]);
        expect(jws.getParsedPayload()).to.eql(payload);
        expect(jws.getParsedHeader()).to.eql(header);
    });

    it('should fail to sign with wrong password', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem),
            header = { alg: alg },
            payload = { foo: 'bar', wup: 90 };

        function gen()
        {
            new jsjws.JWS().generateJWSByKey(header, payload, priv_key, 'foobar');
        }

        if (pass)
        {
            expect(gen).to.throw();
        }
        else
        {
            gen();
        }
    });

    it('should fail to convert to public key with wrong password', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem);

        function convert()
        {
            priv_key.toPublicKey('foobar');
        }

        if (pass)
        {
            expect(convert).to.throw();
        }
        else
        {
            convert();
        }
    });

    it('should be able to export encrypted private key', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem),
            priv_pem = priv_key.toPrivatePem(pass, 'foobar', type || 'aes128'),
            priv_key2 = jsjws.createPrivateKey(priv_pem),
            header = { alg: alg },
            payload = { foo: 'bar', wup: 90 },
            sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key2, 'foobar'),
            jws = new jsjws.JWS();

        jws.verifyJWSByKey(sig, priv_key2.toPublicKey('foobar'), [alg]);
        expect(jws.getParsedPayload()).to.eql(payload);
        expect(jws.getParsedHeader()).to.eql(header);
    });

    it('should be able to export encrypted private key that fails without password', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem),
            priv_pem = priv_key.toPrivatePem(pass, 'foobar', type || 'aes128'),
            priv_key2 = jsjws.createPrivateKey(priv_pem),
            header = { alg: alg },
            payload = { foo: 'bar', wup: 90 };

        expect(function ()
        {
            new jsjws.JWS().generateJWSByKey(header, payload, priv_key2);
        }).to.throw();
    });

    it('should fail to export private key with wrong import password', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem);

        function exp()
        {
            priv_key.toPrivatePem('foobar');
        }

        if (pass)
        {
            expect(exp).to.throw();
        }
        else
        {
            exp();
        }
    });

    it('should be able to export unencrypted private key', function ()
    {
        let priv_key = jsjws.createPrivateKey(enc_priv_pem),
            priv_pem = priv_key.toPrivatePem(pass),
            priv_key2 = jsjws.createPrivateKey(priv_pem),
            header = { alg: alg },
            payload = { foo: 'bar', wup: 90 },
            sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key2),
            jws = new jsjws.JWS();

        jws.verifyJWSByKey(sig, priv_key2.toPublicKey(), [alg]);
        expect(jws.getParsedPayload()).to.eql(payload);
        expect(jws.getParsedHeader()).to.eql(header);
    });
});

}

for (let alg of ['RS256', 'PS256'])
{
    encrypted_key('des3', alg, des3_enc_priv_pem, des3_enc_priv_pass);
    encrypted_key('des', alg, des_enc_priv_pem, des_enc_priv_pass);
    encrypted_key('aes128', alg, aes_enc_priv_pem, aes_enc_priv_pass);
    encrypted_key(null, alg, no_enc_priv_pem, no_env_priv_pass);
}
