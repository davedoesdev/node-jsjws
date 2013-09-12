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

global.priv_pem = "-----BEGIN RSA PRIVATE KEY-----                 \n\
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

global.pub_pem = "-----BEGIN PUBLIC KEY-----                       \n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qiw8PWs7PpnnC2BUEoD\n\
RcwXF8pq8XT1/3Hc3cuUJwX/otNefr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB\n\
3sI+pFtjjLBXD/zJmuL3Afg91J9p79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu\n\
89d2V5x02aXB9LqdXkPwiO0eR5s/xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8U\n\
VXNPJnQAfaiKazF+hCdl/syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKI\n\
LwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpj\n\
sQIDAQAB                                                        \n\
-----END PUBLIC KEY-----";

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

