
import sys
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.common import json_decode, base64url_decode, base64url_encode

if sys.version_info < (3, 0):
    _binary_type = str
else:
    _binary_type = bytes

def to_bytes_2and3(s):
    return s if isinstance(s, _binary_type) else s.encode('utf-8')

def generate(header, payload, priv_pem):
    priv_pem = json_decode(priv_pem.replace('\n', '\\n'))
    if priv_pem.startswith("-----BEGIN"):
        priv_key = JWK.from_pem(to_bytes_2and3(priv_pem))
    else:
        priv_key = JWK(kty='oct', k=base64url_encode(priv_pem))
    sig = JWS(payload)
    sig.add_signature(priv_key, protected=header)
    sys.stdout.write(sig.serialize(compact=True))

def verify(sjws, pub_pem):
    sjws = json_decode(sjws)
    pub_pem = json_decode(pub_pem.replace('\n', '\\n'))
    if pub_pem.startswith("-----BEGIN"):
        pub_key = JWK.from_pem(to_bytes_2and3(pub_pem))
    else:
        pub_key = JWK(kty='oct', k=base64url_encode(pub_pem))
    sig = JWS()
    sig.deserialize(sjws, pub_key)
    sys.stdout.write(base64url_decode(json_decode(sig.serialize())['payload']))
