/**
# node-jsjws&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/node-jsjws.png)](https://travis-ci.org/davedoesdev/node-jsjws) [![NPM version](https://badge.fury.io/js/jsjws.png)](http://badge.fury.io/js/jsjws)

Node.js wrapper around [jsjws](https://github.com/kjur/jsjws) (a [JSON Web Signature](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-14) library).

- Uses [crypto](http://nodejs.org/api/crypto.html) for performance. From `node-jsjws` version 3, at least Node.js version 8 is required and the dependency on [ursa](https://github.com/Obvious/ursa) has been removed.
- **Note:** Versions 2.0.0 and later fix [a vulnerability](https://www.timmclean.net/2015/02/25/jwt-alg-none.html) in JSON Web Signature and JSON Web Token verification so please upgrade if you're using this functionality. The API has changed so you will need to update your application. [verifyJWSByKey](#jwsprototypeverifyjwsbykeyjws-key-allowed_algs) and [verifyJWTByKey](#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) now require you to specify which signature algorithms are allowed.
- Supports [__RS256__, __RS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.3), [__PS256__, __PS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.5), [__HS256__, __HS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.2) and [__none__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.6) signature algorithms.
- Basic [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) functionality.
- Unit tests, including tests for interoperability with [node-jws](https://github.com/brianloveswords/node-jws), [python-jws](https://github.com/brianloveswords/python-jws) and jsjws in the browser (using [PhantomJS](http://phantomjs.org/)).

Example:

```javascript
var jsjws = require('jsjws');
var key = jsjws.generatePrivateKey(2048, 65537);
var header = { alg: 'PS256' };
var payload = { foo: 'bar', wup: 90 };
var sig = new jsjws.JWS().generateJWSByKey(header, payload, key);
var jws = new jsjws.JWS();
assert(jws.verifyJWSByKey(sig, key, ['PS256']));
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
var priv_pem = key.toPrivatePem();
var pub_pem = key.toPublicPem();
var header = { alg: 'RS256' };
var payload = JSON.stringify('hello world!');
var priv_key = jsjws.createPrivateKey(priv_pem);
var pub_key = jsjws.createPublicKey(pub_pem);
var sig = new jsjws.JWS().generateJWSByKey(header, payload, priv_key);
var jws = new jsjws.JWS();
assert(jws.verifyJWSByKey(sig, pub_key, ['RS256']));
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

[Instanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://rawgit.davedoesdev.com/davedoesdev/node-jsjws/master/coverage/lcov-report/index.html).

Coverage is so low because most of the [jsjws](https://github.com/kjur/jsjws) code included in node-jsjws is not used. To keep things simple I've included whole files rather than split out individual functions.

## Benchmarks

```shell
grunt bench
```

Here are some results on a laptop with an Intel Core i5-4300M 2.6Ghz CPU and 8Gb RAM running Ubuntu 17.04.

In the tables, _jsjws-fast_ uses [crypto](http://nodejs.org/api/crypto.html) for signature generation and verification whereas _jsjws-slow_ does everything in Javascript. The algorithm used was __RS256__.

generate_key x10|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-slow|23,474|2,347,432,153|-
jsjws-fast|25,305|2,530,504,075|8

generate_signature x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|1,260|1,260,395|-
jsjws-slow|33,824|33,824,339|2,584

load_key x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|5|5,035|-
jsjws-slow|142|142,297|2,726

verify_signature x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
jsjws-fast|98|98,050|-
jsjws-slow|1,100|1,100,369|1,022

# API
*/

/*global PrivateKey, PublicKey */
/*jslint node: true, unparam: true */
"use strict";

/**
Create a private RSA key from a PEM-format string.

@param {String} pem Private key to load, in PEM Base64 format.
@param {String} [password] Password used to decrypt the key. If not specified, the key is assumed not to be encrypted.
@return {PrivateKey} The private key object.
*/
function createPrivateKey(pem, password) { return undefined; }

/**
Create a public RSA key from a PEM-format string.

@param {String} pem Public key to load, in PEM Base64 format.
@param {String} [encoding] How the key in `pem` is encoded (e.g. `utf8`, `ascii`). Defaults to `utf8`.
@return {PublicKey} The public key object.
*/
function createPublicKey(pem) { return undefined; }

/**
Generate a new RSA private key (keypair). The private key also contains the public key component.

@param {String} modulusBits Number of bits in the modulus (typically 2048).
@param {Integer} exponent Exponent value (typically 65537).
@return {PrivateKey} The private key (keypair) object.
*/
function generatePrivateKey(modulus, exponent) { return undefined; }

/**
Convert a private RSA key to a PEM-format string.

@return {String} PEM Base64 format string.
*/
PrivateKey.prototype.toPrivatePem = function () { return undefined; };

/**
Convert a public RSA key to a PEM-format string. Note: you can also call `toPublicPem` on a `PrivateKey` (because private keys contain the public key data too).

@return {String} PEM Base64 format string.
*/
PublicKey.prototype.toPublicPem = function () { return undefined; };

/**
Create a new JWS object which can be used to generate or verify JSON Web Signatures.

@constructor
*/
function JWS () { return undefined; }

/**
Generate a JSON Web Signature.

@param {Object} header Metadata describing the payload. If you pass a string, it's assumed to be a JSON serialization of the metadata. The metadata should contain at least the following property:

  - `{String} alg` The algorithm to use for generating the signature. `RS256`, `RS512`, `PS256`, `PS512`, `HS256`, `HS512` and `none` are supported.

@param {Object} payload The data you want included in the signature. If you pass a string, it's assumed to be a JSON serialization of the data. So if you want to include just a string, call `JSON.stringify` on it first.

@param {PrivateKey|String|Buffer} key The private key to be used to do the signing. For `HS256` and `HS512`, pass a string or `Buffer`. For `none`, this argument is ignored.

@return {String} The JSON Web Signature. Note this includes the header, payload and cryptographic signature.
*/
JWS.prototype.generateJWSByKey = function (header, payload, key) { return undefined; };

/**
Verify a JSON Web Signature.

@param {String} jws The JSON Web Signature to verify.

@param {PublicKey} key The public key to be used to verify the signature. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` and `allowed_algs` contains `none` then the signature will not be verified.

@param {Array|Object} allowed_algs Algorithms expected to be used to sign the signature. If you pass an `Object` then its properties define the set of algorithms expected.

@return {Boolean} `true` if the signature was verified successfully. The JWS must pass the following tests:

- Its header must contain a property `alg` with a value in `allowed_algs`.

- Its signature must verify using `key` (unless its algorithm is `none` and `none` is in `allowed_algs`).

@throws {Error} If the signature failed to verify.
*/
JWS.prototype.verifyJWSByKey = function (jws, key, allowed_algs) { return undefined; };

/**
Get the header (metadata) from a JSON Web Signature. Call this after verifying the signature (with JWS.prototype.verifyJWSByKey).

@return {Object} The header.
*/
JWS.prototype.getParsedHeader = function () { return undefined; };

/**
Get the header (metadata) from a JSON Web Signature. Call this after verifying the signature (with JWS.prototype.verifyJWSByKey).

@return {String} The JSON-encoded header.
*/
JWS.prototype.getUnparsedHeader = function () { return undefined; };

/**
Get the payload (data) from a JSON Web Signature. Call this after verifying the signature (with JWS.prototype.verifyJWSByKey).

@return {Object} The payload.
*/
JWS.prototype.getParsedPayload = function () { return undefined; };

/**
Get the payload (data) from a JSON Web Signature. Call this after verifying the signature (with JWS.prototype.verifyJWSByKey).

@return {String} The JSON-encoded payload.
*/
JWS.prototype.getUnparsedPayload = function () { return undefined; };

/**
Process a JSON Web Signature without verifying it. Call this before JWS.prototype.verifyJWSByKey if you need access to the header or data in the signature before verifying it. For example, the metadata might identify the issuer such that you can retrieve the appropriate public key.

@param {String} jws The JSON Web Signature to process.
*/
JWS.prototype.processJWS = function (jws) { return undefined; };

/**
Create a new JWT object which can be used to generate or verify JSON Web Tokens.

Inherits from JWS.

@constructor
@augments JWS
*/

function JWT () { return undefined; }

/**
Generate a JSON Web Token.

@param {Object} header Metadata describing the token's claims. Pass a map of key-value pairs. The metadata should contain at least the following property:

  - `{String} alg` The algorithm to use for generating the signature. `RS256`, `RS512`, `PS256`, `PS512`, `HS256`, `HS512` and `none` are supported.

@param {Object} claims The claims you want included in the signature. Pass a map of key-value pairs.

@param {Date} expires When the token expires.

@param {Date} [not_before] When the token is valid from. Defaults to current time.

@param {Integer} [jti_size] Size in bytes of a unique token ID to put into the token (can be used to detect replay attacks). Defaults to 16 (128 bits). Specify 0 or `null` to omit the JTI from the token.

@param {PrivateKey|String|Buffer} key The private key to be used to sign the token. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` then the token will be returned with an empty cryptographic signature and `header.alg` will be forced to the value `none`.

@return {String} The JSON Web Token. Note this includes the header, claims and cryptographic signature.  The following extra claims are added, per the [JWT spec](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html):

- `{IntDate} exp` The UTC expiry date and time of the token, in number of seconds from 1970-01-01T0:0:0Z UTC.

- `{IntDate} nbf` The UTC valid-from date and time of the token.

- `{IntDate} iat` The UTC date and time at which the token was generated.

- `{String} jti` A unique identifier for the token.
*/
JWT.prototype.generateJWTByKey = function (header, claims, expires, not_before, key) { return undefined; };

/**
Verify a JSON Web Token.

@param {String} jwt The JSON Web Token to verify.

@param {Object} [options] Optional parameters for the verification:

  - `{Integer} iat_skew` The amount of leeway (in seconds) to allow between the issuer's clock and the verifier's clock when verifiying that the token was generated in the past. Defaults to 0.

  - `{Boolean} checks_optional` Whether the token must contain the `typ` header property and the `iat`, `nbf` and `exp` claim properties. Defaults to `false`.

@param {PublicKey} key The public key to be used to verify the token. For `HS256` and `HS512`, pass a string or `Buffer`. Note: if you pass `null` and `allowed_algs` contains `none` then the token's signature will not be verified.

@param {Array|Object} allowed_algs Algorithms expected to be used to sign the token. If you pass an `Object` then its properties define the set of algorithms expected.

@return {Boolean} `true` if the token was verified successfully. The token must pass the following tests:

- Its header must contain a property `alg` with a value in `allowed_algs`.

- Its signature must verify using `key` (unless its algorithm is `none` and `none` is in `allowed_algs`).

- If the corresponding property is present or `options.checks_optional` is `false`:

    - Its header must contain a property `typ` with the value `JWT`.

    - Its claims must contain a property `iat` which represents a date in the past (taking into account `options.iat_skew`).

    - Its claims must contain a property `nbf` which represents a date in the past.

    - Its claims must contain a property `exp` which represents a date in the future.

@throws {Error} If the token failed to verify.
*/
JWT.prototype.verifyJWTByKey = function (jwt, options, key, allowed_algs) { return undefined; };

/**
A class for handling X509 certificates. This is included as a utility for extracting public keys and information from a certificate.

Please see the [jsjws reference](http://kjur.github.io/jsrsasign/api/symbols/X509.html) for full details of the static and instance methods available on `X509`.

See [this unit test](test/cert_spec.js) for an example of extracting the public key from a certificate in order to verify a JSON Web Signature.

@constructor
*/
function X509 () { return undefined; }


