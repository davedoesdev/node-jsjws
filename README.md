# node-jsjws&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/node-jsjws.png)](https://travis-ci.org/davedoesdev/node-jsjws) [![Coverage Status](https://coveralls.io/repos/davedoesdev/node-jsjws/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/node-jsjws?branch=master) [![NPM version](https://badge.fury.io/js/jsjws.png)](http://badge.fury.io/js/jsjws)

Node.js wrapper around [jsjws](https://github.com/kjur/jsjws) (a [JSON Web Signature](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-14) library).

- Uses [ursa](https://github.com/Obvious/ursa) for performance.
- Supports [__RS256__, __RS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.3), [__PS256__, __PS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.5), [__HS256__, __HS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.2) and [__none__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.6) signature algorithms.
- Basic [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) functionality.
- Unit tests, including tests for interoperability with [jwcrypto](https://github.com/mozilla/jwcrypto), [python-jws](https://github.com/brianloveswords/python-jws) and jsjws in the browser (using [PhantomJS](http://phantomjs.org/)).

Example:

```javascript
var jsjws = require('jsjws');
var key = jsjws.generatePrivateKey(2048, 65537);
var header = { alg: 'PS256' };
var payload = { foo: 'bar', wup: 90 };
var sig = new jsjws.JWS().generateJWSByKey(header, payload, key);
var jws = new jsjws.JWS();
assert(jws.verifyJWSByKey(sig, key));
assert.deepEqual(jws.getParsedHeader(), header);
assert.deepEqual(jws.getParsedPayload(), payload);
```

The API is described [here](#tableofcontents).

## Installation

```shell
npm install jsjws
```

## Another Example

You can read and write keys from and to [PEM-format](http://www.openssl.org/docs/crypto/pem.html) strings:

```javascript
var jsjws = require('jsjws');
var key = jsjws.generatePrivateKey(2048, 65537);
var priv_pem = key.toPrivatePem('utf8');
var pub_pem = key.toPublicPem('utf8');
var header = { alg: 'RS256' };
var payload = JSON.stringify('hello world!');
var priv_key = jsjws.createPrivateKey(priv_pem, 'utf8');
var pub_key = jsjws.createPublicKey(pub_pem, 'utf8');
var sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key);
var jws = new jsjws.JWS();
assert(jws.verifyJWSByKey(sig, pub_key));
assert.deepEqual(jws.getParsedHeader(), header);
assert.equal(jws.getUnparsedPayload(), payload);
```

## Licence

[MIT](LICENCE)

## Tests

```shell
grunt test
```

## Lint

```shell
grunt lint
```

## Code Coverage

```shell
grunt coverage
```

[Instanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://githubraw.herokuapp.com/davedoesdev/node-jsjws/master/coverage/lcov-report/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/node-jsjws).

Coverage is so low because most of the [jsjws](https://github.com/kjur/jsjws) code included in node-jsjws is not used. To keep things simple I've included whole files rather than split out individual functions.

## Benchmarks

```shell
grunt bench
```

Here are some results on a laptop with an Intel Core i5-3210M 2.5Ghz CPU and 6Gb RAM running Ubuntu 13.04.

In the tables, _jsjws-fast_ uses [ursa](https://github.com/Obvious/ursa) ([OpenSSL](http://www.openssl.org/)) for crypto whereas _jsjws-slow_ does everything in Javascript. The algorithm used was __RS256__ because _jwcrypto_ doesn't support __PS256__.

generate_key x10|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jwcrypto|1,183|118,263,125|-
jsjws-fast|1,296|129,561,098|10
jsjws-slow|32,090|3,209,012,197|2,613

generate_signature x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|2,450|2,450,449|-
jwcrypto|4,786|4,786,343|95
jsjws-slow|68,589|68,588,742|2,699

load_key x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|46|45,996|-
jsjws-slow|232|232,481|405

verify_signature x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|134|134,032|-
jwcrypto|173|173,194|29
jsjws-slow|1,706|1,705,810|1,173

# API

<a name="tableofcontents"></a>

## Key functions
- <a name="toc_createprivatekeypem-password-encoding"></a>[createPrivateKey](#createprivatekeypem-password-encoding)
- <a name="toc_createpublickeypem-encoding"></a>[createPublicKey](#createpublickeypem-encoding)
- <a name="toc_generateprivatekeymodulusbits-exponent"></a>[generatePrivateKey](#generateprivatekeymodulusbits-exponent)
- <a name="toc_privatekeyprototypetoprivatepemencoding"></a><a name="toc_privatekeyprototype"></a><a name="toc_privatekey"></a>[PrivateKey.prototype.toPrivatePem](#privatekeyprototypetoprivatepemencoding)
- <a name="toc_publickeyprototypetopublicpemencoding"></a><a name="toc_publickeyprototype"></a><a name="toc_publickey"></a>[PublicKey.prototype.toPublicPem](#publickeyprototypetopublicpemencoding)

## JSON Web Signature functions
- <a name="toc_jws"></a>[JWS](#jws)
- <a name="toc_jwsprototypegeneratejwsbykeyheader-payload-key"></a><a name="toc_jwsprototype"></a>[JWS.prototype.generateJWSByKey](#jwsprototypegeneratejwsbykeyheader-payload-key)
- <a name="toc_jwsprototypeverifyjwsbykeyjws-key"></a>[JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key)
- <a name="toc_jwsprototypegetparsedheader"></a>[JWS.prototype.getParsedHeader](#jwsprototypegetparsedheader)
- <a name="toc_jwsprototypegetunparsedheader"></a>[JWS.prototype.getUnparsedHeader](#jwsprototypegetunparsedheader)
- <a name="toc_jwsprototypegetparsedpayload"></a>[JWS.prototype.getParsedPayload](#jwsprototypegetparsedpayload)
- <a name="toc_jwsprototypegetunparsedpayload"></a>[JWS.prototype.getUnparsedPayload](#jwsprototypegetunparsedpayload)
- <a name="toc_jwsprototypeprocessjwsjws"></a>[JWS.prototype.processJWS](#jwsprototypeprocessjwsjws)

## JSON Web Token functions
- <a name="toc_jwt"></a>[JWT](#jwt)
- <a name="toc_jwtprototypegeneratejwtbykeyheader-claims-expires-not_before-key"></a><a name="toc_jwtprototype"></a>[JWT.prototype.generateJWTByKey](#jwtprototypegeneratejwtbykeyheader-claims-expires-not_before-key)
- <a name="toc_jwtprototypeverifyjwtbykeyjwt-options-key"></a>[JWT.prototype.verifyJWTByKey](#jwtprototypeverifyjwtbykeyjwt-options-key)
- <a name="toc_x509"></a>[X509](#x509)

-----

## createPrivateKey(pem, [password], [encoding])

> Create a private RSA key from a PEM-format string.

**Parameters:**

- `{String} pem` Private key to load, in PEM Base64 format.
- `{String} [password]` Password used to decrypt the key. If not specified, the key is assumed not to be encrypted.
- `{String} [encoding]` How the key in `pem` is encoded (e.g. `utf8`, `ascii`). Defaults to `utf8`.

**Return:**

`{PrivateKey}` The private key object.

<sub>Go: [TOC](#tableofcontents)</sub>

## createPublicKey(pem, [encoding])

> Create a public RSA key from a PEM-format string.

**Parameters:**

- `{String} pem` Public key to load, in PEM Base64 format.
- `{String} [encoding]` How the key in `pem` is encoded (e.g. `utf8`, `ascii`). Defaults to `utf8`.

**Return:**

`{PublicKey}` The public key object.

<sub>Go: [TOC](#tableofcontents)</sub>

## generatePrivateKey(modulusBits, exponent)

> Generate a new RSA private key (keypair). The private key also contains the public key component.

**Parameters:**

- `{String} modulusBits` Number of bits in the modulus (typically 2048).
- `{Integer} exponent` Exponent value (typically 65537).

**Return:**

`{PrivateKey}` The private key (keypair) object.

<sub>Go: [TOC](#tableofcontents)</sub>

<a name="privatekeyprototype"></a>

<a name="privatekey"></a>

## PrivateKey.prototype.toPrivatePem(encoding)

> Convert a private RSA key to a PEM-format string.

**Parameters:**

- `{String} encoding` How to encode the returned string. Defaults to returning a Node.js [Buffer](http://nodejs.org/api/buffer.html) object.

**Return:**

`{String}` PEM Base64 format string.

<sub>Go: [TOC](#tableofcontents) | [PrivateKey.prototype](#toc_privatekeyprototype)</sub>

<a name="publickeyprototype"></a>

<a name="publickey"></a>

## PublicKey.prototype.toPublicPem(encoding)

> Convert a public RSA key to a PEM-format string. Note: you can also call `toPublicPem` on a `PrivateKey` (because private keys contain the public key data too).

**Parameters:**

- `{String} encoding` How to encode the returned string. Defaults to returning a Node.js [Buffer](http://nodejs.org/api/buffer.html) object.

**Return:**

`{String}` PEM Base64 format string.

<sub>Go: [TOC](#tableofcontents) | [PublicKey.prototype](#toc_publickeyprototype)</sub>

## JWS()

> Create a new JWS object which can be used to generate or verify JSON Web Signatures.

<sub>Go: [TOC](#tableofcontents)</sub>

<a name="jwsprototype"></a>

## JWS.prototype.generateJWSByKey(header, payload, key)

> Generate a JSON Web Signature.

**Parameters:**

- `{Object} header` Metadata describing the payload. If you pass a string, it's assumed to be a JSON serialization of the metadata. The metadata should contain at least the following property:


  - `{String} alg` The algorithm to use for generating the signature. `RS256`, `RS512`, `PS256`, `PS512`, `HS256`, `HS512` and `none` are supported.


- `{Object} payload` The data you want included in the signature. If you pass a string, it's assumed to be a JSON serialization of the data. So if you want to include just a string, call `JSON.stringify` on it first.



- `{PrivateKey | String | Buffer} key` The private key to be used to do the signing. For `HS256` and `HS512`, pass a string or `Buffer`. For `none`, this argument is ignored.



**Return:**

`{String}` The JSON Web Signature. Note this includes the header, payload and cryptographic signature.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.verifyJWSByKey(jws, key)

> Verify a JSON Web Signature.

**Parameters:**

- `{String} jws` The JSON Web Signature to verify.



- `{PublicKey} key` The public key to be used to verify the signature. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` then the signature will not be verified.



**Return:**

`{Boolean}` `true` if the signature was verified successfully using the public key or the JSON Web Signature's algorithm is `none`.



**Throws:**

- `{Error}` If the signature failed to verify.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.getParsedHeader()

> Get the header (metadata) from a JSON Web Signature. Call this after verifying the signature (with [JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key)).

**Return:**

`{Object}` The header.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.getUnparsedHeader()

> Get the header (metadata) from a JSON Web Signature. Call this after verifying the signature (with [JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key)).

**Return:**

`{String}` The JSON-encoded header.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.getParsedPayload()

> Get the payload (data) from a JSON Web Signature. Call this after verifying the signature (with [JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key)).

**Return:**

`{Object}` The payload.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.getUnparsedPayload()

> Get the payload (data) from a JSON Web Signature. Call this after verifying the signature (with [JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key)).

**Return:**

`{String}` The JSON-encoded payload.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWS.prototype.processJWS(jws)

> Process a JSON Web Signature without verifying it. Call this before [JWS.prototype.verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key) if you need access to the header or data in the signature before verifying it. For example, the metadata might identify the issuer such that you can retrieve the appropriate public key.

**Parameters:**

- `{String} jws` The JSON Web Signature to process.

<sub>Go: [TOC](#tableofcontents) | [JWS.prototype](#toc_jwsprototype)</sub>

## JWT()

> Create a new JWT object which can be used to generate or verify JSON Web Tokens.

Inherits from [JWS](#jws).

<sub>Go: [TOC](#tableofcontents)</sub>

<a name="jwtprototype"></a>

## JWT.prototype.generateJWTByKey(header, claims, expires, [not_before], key)

> Generate a JSON Web Token.

**Parameters:**

- `{Object} header` Metadata describing the token's claims. Pass a map of key-value pairs. The metadata should contain at least the following property:


  - `{String} alg` The algorithm to use for generating the signature. `RS256`, `RS512`, `PS256`, `PS512`, `HS256`, `HS512` and `none` are supported.


- `{Object} claims` The claims you want included in the signature. Pass a map of key-value pairs.



- `{Date} expires` When the token expires.



- `{Date} [not_before]` When the token is valid from. Defaults to current time.



- `{PrivateKey | String | Buffer} key` The private key to be used to sign the token. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` then the token will be returned with an empty cryptographic signature and `header.alg` will be forced to the value `none`.



**Return:**

`{String}` The JSON Web Token. Note this includes the header, claims and cryptographic signature. The following extra claims are added, per the [JWT spec](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html):


- `{IntDate} exp` The UTC expiry date and time of the token, in number of seconds from 1970-01-01T0:0:0Z UTC.

- `{IntDate} nbf` The UTC valid-from date and time of the token.

- `{IntDate} iat` The UTC date and time at which the token was generated.

- `{String} jti` A unique identifier for the token.

<sub>Go: [TOC](#tableofcontents) | [JWT.prototype](#toc_jwtprototype)</sub>

## JWT.prototype.verifyJWTByKey(jwt, [options], key)

> Verify a JSON Web Token.

**Parameters:**

- `{String} jwt` The JSON Web Token to verify.



- `{Object} [options]` Optional parameters for the verification:


  - `{Integer} iat_skew` The amount of leeway (in seconds) to allow between the issuer's clock and the verifier's clock when verifiying that the token was generated in the past. Defaults to 0.

  - `{Boolean} checks_optional` Whether the token must contain the `typ` header property and the `iat`, `nbf` and `exp` claim properties. Defaults to `false`.


- `{PublicKey} key` The public key to be used to verify the token. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` then the token's signature will not be verified.



**Return:**

`{Boolean}` `true` if the token was verified successfully. The token must pass the following tests:


Its signature must verify using the public key or its algorithm must be `none`.

If the corresponsing property is present or `options.checks_optional` is `false`:

- Its header must contain a property `typ` with the value `JWT`.

- Its claims must contain a property `iat` which represents a date in the past (taking into account `options.iat_skew`).

- Its claims must contain a property `nbf` which represents a date in the past.

- Its claims must contain a property `exp` which represents a date in the future.


**Throws:**

- `{Error}` If the token failed to verify.

<sub>Go: [TOC](#tableofcontents) | [JWT.prototype](#toc_jwtprototype)</sub>

## X509()

> A class for handling X509 certificates. This is included as a utility for extracting public keys and information from a certificate.

Please see the [jsjws reference](http://kjur.github.io/jsrsasign/api/symbols/X509.html) for full details of the static and instance methods available on `X509`.

See [this unit test](blob/master/test/cert_spec.js) for an example of extracting the public key from a certificate in order to verify a JSON Web Signature.

<sub>Go: [TOC](#tableofcontents)</sub>

_&mdash;generated by [apidox](https://github.com/codeactual/apidox)&mdash;_
