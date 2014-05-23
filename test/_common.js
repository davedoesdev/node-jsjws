/*global payload, priv_keys, jsjws, priv_pem, pub_keys, pub_pem */
/*jslint node: true */

global.jsjws = require('..');
global.expect = require('chai').expect;
global.wd = require('wd');
global.sinon = require('sinon');

global.payload = {
    iss: "joe",
    exp: 1300819380,
    "http://example.com/is_root": true
};

global.payload2 = {
    foo: "joe",
    bar: 2398742.23092384,
    "http://example.com/is_root": true
};

global.spayload = JSON.stringify(payload);

// keys from jsjws samples

global.priv_pem = "-----BEGIN RSA PRIVATE KEY-----              \n\
MIIEogIBAAKCAQEA4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1/3Hc3cuUJwX/otNe\n\
fr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI+pFtjjLBXD/zJmuL3Afg91J9p\n\
79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s/\n\
xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF+hCdl/syrIh0K\n\
CZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU\n\
5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQIDAQABAoIBAF2sU/wxvHbwAhQE\n\
pnXVMMcO0thtOodxzBz3JM2xThhWnVDgxCPkAhWq2X0NSm5n9BY5ajwyxYH6heTc\n\
p6lagtxaMONiNaE2W7TqxzMw696vhnYyL+kH2e9+owEoKucXz4QYatqsJIQPb2vM\n\
0h+DfFAgUvNgYNZ2b9NBsLn9oBImDfYueHyqpRGTdX5urEVtmQz029zaC+jFc7BK\n\
Y6qBRSTwFwnVgE+Td8UgdrO3JQ/0Iwk/lkphnhls/BYvdNC5O8oEppozNVmMV8jm\n\
61K+agOh1KD8ky60iQFjo3VdFpUjI+W0+sYiYpDb4+Z9OLOTK/5J2EBAGim9siyd\n\
gHspx+UCgYEA9+t5Rs95hG9Q+6mXn95hYduPoxdFCIFhbGl6GBIGLyHUdD8vmgwP\n\
dHo7Y0hnK0NyXfue0iFBYD94/fuUe7GvcXib93heJlvPx9ykEZoq9DZnhPFBlgIE\n\
SGeD8hClazcr9O99Fmg3e7NyTuVou+CIublWWlFyN36iamP3a08pChsCgYEA6gvT\n\
pi/ZkYI1JZqxXsTwzAsR1VBwYslZoicwGNjRzhvuqmqwNvK17dnSQfIrsC2VnG2E\n\
UbE5EIAWbibdoL4hWUpPx5Tl096OjC3qBR6okAxbVtVEY7Rmv7J9RwriXhtD1DYp\n\
eBvo3eQonApFkfI8Lr2kuKGIgwzkZ72QLXsKJiMCgYBZXBCci0/bglwIObqjLv6e\n\
zQra2BpT1H6PGv2dC3IbLvBq7hN0TQCNFTmusXwuReNFKNq4FrB/xqEPusxsQUFh\n\
fv2Il2QoI1OjUE364jy1RZ7Odj8TmKp+hoEykPluybYYVPIbT3kgJy/+bAXyIh5m\n\
Av2zFEQ86HIWMu4NSb0bHQKBgETEZNOXi52tXGBIK4Vk6DuLpRnAIMVl0+hJC2DB\n\
lCOzIVUBM/VxKvNP5O9rcFq7ihIEO7SlFdc7S1viH4xzUOkjZH2Hyl+OLOQTOYd3\n\
kp+AgfXpg8an4ujAUP7mu8xaxns7zsNzr+BCgYwXmIlhWz2Aiz2UeL/IsfOpRwuV\n\
801xAoGADQB84MJe/X8xSUZQzpn2KP/yZ7C517qDJjComGe3mjVxTIT5XAaa1tLy\n\
T4mvpSeYDJkBD8Hxr3fB1YNDWNbgwrNPGZnUTBNhxIsNLPnV8WySiW57LqVXlggH\n\
vjFmyDdU5Hh6ma4q+BeAqbXZSJz0cfkBcBLCSe2gIJ/QJ3YJVQI=            \n\
-----END RSA PRIVATE KEY-----";

global.pub_pem = "-----BEGIN PUBLIC KEY-----                    \n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qiw8PWs7PpnnC2BUEoD\n\
RcwXF8pq8XT1/3Hc3cuUJwX/otNefr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB\n\
3sI+pFtjjLBXD/zJmuL3Afg91J9p79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu\n\
89d2V5x02aXB9LqdXkPwiO0eR5s/xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8U\n\
VXNPJnQAfaiKazF+hCdl/syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKI\n\
LwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpj\n\
sQIDAQAB                                                        \n\
-----END PUBLIC KEY-----";

global.cert_pem = "-----BEGIN CERTIFICATE-----                  \n\
MIIDBzCCAe+gAwIBAgIJAOh9+lCC+Oq6MA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV\n\
BAMMD25vZGUtanNqd3MgdGVzdDAeFw0xNDA1MjMwNjI4MTFaFw0yNDA1MjAwNjI4\n\
MTFaMBoxGDAWBgNVBAMMD25vZGUtanNqd3MgdGVzdDCCASIwDQYJKoZIhvcNAQEB\n\
BQADggEPADCCAQoCggEBAOIgQ7TnvviwUkdSY+jG1A5sPGBfRdEZATr3+Fd6RGqM\n\
oKDy/LVDB1XQpOjID0cDU+iu6SHcEPFgFNlE8OTCwAMSc+k2wHaqOGbE7pr+lqvM\n\
bUMvk6osnb7Wk1Lyd2wncr+3btK7YKikagVyrKLsIS3DDpN7W6CLBHDzoHVe3Z57\n\
N37/u8XWLkQPYAAiesfEdbi7YjptVrq2V0HuC8Pg+wiHfnekQkuFXM+HB3KpU4ZP\n\
4iJFlRc572ebMxE5mWy95zLT9fXKEnhu7hsJm8SIbvNE7C5CDadvLtWN/CkCIYUM\n\
tp+8WaQiOsGCe/rKlyWzVmvvwG8mLqzyeqTXLEncCEkCAwEAAaNQME4wHQYDVR0O\n\
BBYEFJS/l4UF22cs51xISSQtG5qD4mx1MB8GA1UdIwQYMBaAFJS/l4UF22cs51xI\n\
SSQtG5qD4mx1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAK4mfm0p\n\
CJEbPaethb1aRSK60lDa/dqKxdad5wMxvQ/w0PFqkcuooTsBiI6Xl7Nwi3pE/SoC\n\
QF9ay+TTS7qd6Zx2bNZg9ndP1NoQ9xo0fY/vX2JBxbSmvWjgFCyjTkCJbypFuhag\n\
E6EwoakJeWJNjSkFv+QOI34gj5dkLZ5e1VjNY3yHYc6poxNVqvjQxRzYB0iBL/6n\n\
Hpxo5N/+c7cTlqJmYR8tS3GnQYKywgBEAsWaA4PfkWfbk4a7h2sqdbWlVHyUMeqZ\n\
c4hsmSDKQXCbNAm/KXVJeR2kKduQx+H+P8qjgaGPyGJNt2qRkZoBkxGab3o4959P\n\
QLv+nMzHS07/MdU=                                                \n\
-----END CERTIFICATE-----";

global.cert_pub_pem = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4iBDtOe++LBSR1Jj6MbU\n\
Dmw8YF9F0RkBOvf4V3pEaoygoPL8tUMHVdCk6MgPRwNT6K7pIdwQ8WAU2UTw5MLA\n\
AxJz6TbAdqo4ZsTumv6Wq8xtQy+TqiydvtaTUvJ3bCdyv7du0rtgqKRqBXKsouwh\n\
LcMOk3tboIsEcPOgdV7dnns3fv+7xdYuRA9gACJ6x8R1uLtiOm1WurZXQe4Lw+D7\n\
CId+d6RCS4Vcz4cHcqlThk/iIkWVFznvZ5szETmZbL3nMtP19coSeG7uGwmbxIhu\n\
80TsLkINp28u1Y38KQIhhQy2n7xZpCI6wYJ7+sqXJbNWa+/AbyYurPJ6pNcsSdwI\n\
SQIDAQAB\n\
-----END PUBLIC KEY-----\n";

global.cert_priv_pem = "-----BEGIN PRIVATE KEY-----             \n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDiIEO05774sFJH\n\
UmPoxtQObDxgX0XRGQE69/hXekRqjKCg8vy1QwdV0KToyA9HA1Porukh3BDxYBTZ\n\
RPDkwsADEnPpNsB2qjhmxO6a/parzG1DL5OqLJ2+1pNS8ndsJ3K/t27Su2CopGoF\n\
cqyi7CEtww6Te1ugiwRw86B1Xt2eezd+/7vF1i5ED2AAInrHxHW4u2I6bVa6tldB\n\
7gvD4PsIh353pEJLhVzPhwdyqVOGT+IiRZUXOe9nmzMROZlsvecy0/X1yhJ4bu4b\n\
CZvEiG7zROwuQg2nby7VjfwpAiGFDLafvFmkIjrBgnv6ypcls1Zr78BvJi6s8nqk\n\
1yxJ3AhJAgMBAAECggEAVW8tRZddfuZXX90QJG2ixwQ714mHflX9MgNoT9zBJqSV\n\
N9o2gmGdzt1ywQR9SS5HsJ0NNh7IQ/oyRliWz0eJdl+tbYqjMvJjNujm4aaY1LX6\n\
/ixmlSAgRW8a4Hb9id5pq2eptnLXNUBRUleeRDwE2R5eTniICOMdPXO+xzmdb/eV\n\
yIUYq/hATh4y6i2XezoGFnw72071b7RDFbY6eAd7nNnjXWAA+fZrtTAhCQFYkj6X\n\
AbcX74WIZzAzJ/KO8g+WiEogekOBA4MlwypdFaC0JElyR2pdP6RV0XETJ1lkeIf6\n\
qqyu9+ZEs/iEpgNC6L7GcUuOlzsUtgCYe7XQRGDpUQKBgQD+uJqA8pZahqdoTZIL\n\
j8mUxIDwpvANic7XOsG1YBhm1hj/EOnFs1bEZ29Hmxc4pnVKVNwXQ442U/QtCILA\n\
8XuYbX0YM9JlrBCrgmmgfqBWbCOUyDY9+oOUN8YjFaYF8vMAWq/QBQD9d5qddNwT\n\
Rir+3ojgD/WLu98hG++F6/vdJQKBgQDjQuhFyJ8t6/eQOPbASZJMUU434+AzQWh/\n\
/01WUJMO9Pjut4Mo8Xl2WBxRHJll8vANxpZgQwFBx5/tdQQ7ooffIiJJCi85A3Ot\n\
66JYtzEEnYdGyRiNWgxqKRZYN+Gaynk1tbfQgk1+ZnWWb29w9p9atHjrPXp6IilF\n\
/cBaKDm/VQKBgQDfy3mTyY9oQd5buauTFOXbGzreNQ28F1PvreP7Y06NK5YSo92A\n\
oayeKvKOSyj/0OBESoKEvgn4mZJy7oNS2dfpeGjsFrvIMIEE7zO2mwpsY95vHejq\n\
U2u/kbE3qhGQMIBn00Wc0oioKalipgWluYSVIRfJJLxr5MiJ4m1zkH5dMQKBgQDA\n\
V4FUho7Kg/r8EmosplfuxaWIwhGf78zs//vJgNpl/0msaJ7WiUE+uyYENEtUML+h\n\
OSFOiYdH0Bd4FuClRFLws+gGn1sGSvieC19U7H7NJDI447wm7j6xnuKteWY05wad\n\
QZY4IABMaZU95ESSe/i1ASeSGW9ObRk3hqNE6uStHQKBgQDenJ8NqFxMFH+BRL1T\n\
UbQbW5To7QRhVUjK9VI+jjzVAFnaHD1bfE/IgO2aTe9EV/0ju5V/P0jZqRHO+BI+\n\
f18F3phPpYyOVhQjbCK2lQMdt/7a8ztBX3j+gI3DT2mpek6XAjw9yn6qV57vNwKx\n\
7SeVqfYJUF7VdxISxfNt8IEvvQ==                                    \n\
-----END PRIVATE KEY-----";

global.priv_keys = {};
var rsa_priv_keys = {};
rsa_priv_keys.fast = jsjws.createPrivateKey(priv_pem, 'utf8');
rsa_priv_keys.slow = new jsjws.SlowRSAKey();
rsa_priv_keys.slow.readPrivateKeyFromPEMString(priv_pem);
priv_keys.RS256 = priv_keys.RS512 = priv_keys.PS256 = priv_keys.PS512 = rsa_priv_keys;

global.pub_keys = {};
var rsa_pub_keys = {};
rsa_pub_keys.fast = jsjws.createPublicKey(pub_pem, 'utf8');
rsa_pub_keys.slow = new jsjws.SlowRSAKey();
rsa_pub_keys.slow.readPublicKeyFromPEMString(pub_pem);
pub_keys.RS256 = pub_keys.RS512 = pub_keys.PS256 = pub_keys.PS512 = rsa_pub_keys;

priv_keys.HS256 = pub_keys.HS256 = { default: "some random secret" };
priv_keys.HS512 = pub_keys.HS512 = { default: "another one!" };

global.all_algs = Object.keys(priv_keys);

// signatures generated in browser from jsjws/sample_generate3.html
	
// use jsjws/sample_generate3.html

global.browser_sigs = {
    RS256: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.qCW4l5nfdvBt-yl_OiYRFrKkribqbDbmQ9ULyemAgCNXAAr70hN5-IERIefzySpm6Er4UuX_aXcnIXgMvK-hFMFhLOuJckrDEe1Pz-OzqScvGSJUbeOsd_nB9E2BNVYZrgMESQOifiEyUtWdbzCoMgf9nQg2AEWbVSaPImqQkGp-JZsJsvMUC-3A3RcimGIjLv-A8skyhNufASd6DPgk46Ydqt6vi2L6d2InvZSkhTSsYhbfm9TgrKyA906YHE0zE-asuXAzI1ISPxAjlO8ZhekEvg6teaa-1cSQQdOFj-ZWpqVsEI1YXr7zuvugWQhqfBqqPcT6fP5t3ff8FKwV9w",
    RS512: "eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.RKJjn-vNsR-5iereV2pMyizIJZQHcjswduJory8PsJIG2UQFn7LZ8dnBbaA_CEP9a0Tb-zjo8DHmhhwUmYSLSxTipCjblmYvSw_8beJgEN_oP5wQODTyMu1u4vfAzgwLzqHvfBrI10mONNIWyyiEJQ87QuT7BcDn-n0Jyaw-gFltnpsiMxa4OZihV6SwECpokLaY9dvuJo3bzRvAAoejZXvkYPhaVo2mL2OW03mDjX0Pt_GZ4XLgXWJo7VgwpRUMKppZSWbqNtI9cQZV9a-oT22J_jc9leUXqGzQ8XsMYsIzy4m3AMe2LJqqQd9rzdw89uGUTxq3jBDf8YD-IkSfIg",
    PS256: "eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.BPgi0AnrLxkiFesd8-KuMXYlySs32W3UMFWfbLWXltR5OsNbaxfQ1szIX1pmxinIAMUt5xUCUj0pcCIdLPWoJrqVDrL0WOBOu8bGjHUAWnuZCd8YsiBD-OI1cvmQfK0sLswOPZKb3Fu7odIOSvKf8CLtpNCOZG6P39OokxLcKFtW24K55DAXd9Ag0A0tFjOcEcPxVcUXzy5oBOhVkKFgNeDOUM8zkXIwAIKWZMtcSoFFjfiROZg5oS6kcVnOk3rNp7sfecfqQLS_9fvjVffM5Gst3LmmF3xuWGXRIe1G5hdFeaTQF7GyFVTMO0CaXGqQvtyBfocdAcfNIU0O0VfB8Q",
    PS512: "eyJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.0PwyUD5dNK3WH0HmGKQPmM85l8Vbkf4UXDUrkiTGJx_M1dmMZDWuJ7vu08R37ZFfrJ5s3KziyfPhvU2s04S0pFdIsspGL3FWuebNeb24liWuXiQADtrSJA-rkWpdWG1cZPFUZgG4Si3RRBic3W28T26DuK8FaUDWSb6VL3qv2xQlQmsgQjZRH2UwKMdfjOmVvNxBUPPiSXojPSoWsoA43ilvDGvIC_Ku4IQRn4WfLmLSfsSX2KfZfzrmd6G7N-c0CB_xFXro2kWKxjggnjl_GQvMgbEk3bdeXh1bW6bLamJsrp0lXt5FEy_7UBY-eeYilXd8-aWN4q2djWxSkDP5lw",
    HS256: "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.gC_Pma7iW3LhHx4hYgjAxpW3714qrxzLzW0o0f15S48",
    HS512: "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.7t-DhMEZdUc2yiNAZDCElkRrDd9jDiIiNq39D8HNJ8wAZ-XvejLYr-bSDmKSptSlLaotmx-1VEabUfB0lb_u1w"
};

global.generated_key = jsjws.generatePrivateKey(2048, 65537);

