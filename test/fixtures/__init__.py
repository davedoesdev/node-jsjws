
import jws
import sys
import json
from Crypto.PublicKey import RSA

def generate(header, payload, priv_pem):
    priv_pem = json.loads(priv_pem.replace('\n', '\\n'))
    if priv_pem.startswith("-----BEGIN"):
        priv_key = RSA.importKey(priv_pem)
    else:
        priv_key = priv_pem
    sys.stdout.write("%s.%s.%s" % (
        jws.utils.to_base64(header),
        jws.utils.to_base64(payload),
        jws.sign(header, payload, priv_key, True)
    ))

def verify(sjws, pub_pem):
    sjws = json.loads(sjws)
    pub_pem = json.loads(pub_pem.replace('\n', '\\n'))
    if pub_pem.startswith("-----BEGIN"):
        pub_key = RSA.importKey(pub_pem)
    else:
        pub_key = pub_pem
    header, payload, signature = sjws.split('.')
    header = jws.utils.from_base64(str(header))
    payload = jws.utils.from_base64(str(payload))
    if not jws.verify(header, payload, str(signature), pub_key, True):
        raise "failed to verify signature"
    sys.stdout.write(payload)

