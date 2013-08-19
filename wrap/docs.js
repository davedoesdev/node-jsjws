/**
# node-jsjws&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/node-jsjws.png)](https://travis-ci.org/davedoesdev/node-jwjws) [![Coverage Status](https://coveralls.io/repos/davedoesdev/node-jwjws/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/node-jwjws?branch=master) [![NPM version](https://badge.fury.io/js/jwjws.png)](http://badge.fury.io/js/jwjws)

Node.js wrapper around [jsjws](https://github.com/kjur/jsjws) (a [JSON Web Signature](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-14) library).

- Uses [ursa](https://github.com/Obvious/ursa) for performance.
- Supports [__RS256__, __RS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.3), [__PS256__ and __PS512__](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.5) signature algorithms.
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

```javascript
grunt test
```

## Lint

```javascript
grunt lint
```

## Code Coverage

```javasript
grunt coverage
```

[Instanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://htmlpreview.github.io/?https://github.com/davedoesdev/node-jsjws/blob/master/coverage/lcov-report/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/node-jsjws).

## Benchmarks

```javascript
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
*/

/*global PrivateKey, PublicKey */
/*jslint node: true, unparam: true */
"use strict";

/**
Create a private RSA key from a PEM-format string.

@param {String} pem Private key to load, in PEM Base64 format.
@param {String} [password] Password used to decrypt the key. If not specified, the key is assumed not to be encrypted.
@param {String} [encoding] How the key in __pem__ is encoded (e.g. _utf8_, _ascii_). Defaults to __utf8__.
@return {PrivateKey} The private key object.
*/
function createPrivateKey(pem, password, encoding) { return undefined; }

/**
Create a public RSA key from a PEM-format string.

@param {String} pem Public key to load, in PEM Base64 format.
@param {String} [encoding] How the key in __pem__ is encoded (e.g. __utf8__, __ascii__). Defaults to __utf8__.
@return {PublicKey} The public key object.
*/
function createPublicKey(pem, encoding) { return undefined; }

/**
Generate a new RSA private key (keypair). The private key also contains the public key component.

@param {String} modulusBits Number of bits in the modulus (typically 2048).
@param {Integer} exponent Exponent value (typically 65537).
@return {PrivateKey} The private key (keypair) object.
*/
function generatePrivateKey(modulus, exponent) { return undefined; }

/**
Convert a private RSA key to a PEM-format string.

@param {String} encoding How to encode the returned string. Defaults to returning a Node.js [Buffer](http://nodejs.org/api/buffer.html) object.
@return {String} PEM Base64 format string.
*/
PrivateKey.prototype.toPrivatePem = function (encoding) { return undefined; };

/**
Convert a public RSA key to a PEM-format string. Note: you can also call __toPublicPem__ on a __PrivateKey__ (because private keys contain the public key data too).

@param {String} encoding How to encode the returned string. Defaults to returning a Node.js [Buffer](http://nodejs.org/api/buffer.html) object.
@return {String} PEM Base64 format string.
*/
PublicKey.prototype.toPublicPem = function (encoding) { return undefined; };

/**
Create a new JWS object which can be used to generate or verify JSON Web Signatures.

@constructor
*/
function JWS () { return undefined; }

/**
Generate a JSON Web Signature.

@param {Object} header Metadata describing the payload. If you pass a string, it's assumed to be a JSON serialization of the metadata. The metadata should contain at least the following property:

- `{String} alg` The algorithm to use for generating the signature. __RS256__, __RS512__, __PS256__ and __PS512__ are supported.

@param {Object} payload The data you want included in the signature. If you pass a string, it's assumed to be a JSON serialization of the data. So if you want to include just a string, call __JSON.stringify__ on it first.

@param {PrivateKey} key The private key to be used to do the signing.

@return {String} The JSON Web Signature. Note this includes the header, payload and cryptographic signature.
*/
JWS.prototype.generateJWSByKey = function (header, payload, key) { return undefined; };

/**
Verify a JSON Web Signature.

@param {String} jws The JSON Web Signature to verify.

@param {PublicKey} key The public key to be used to verify the signature.

@return {Boolean} Whether the signature was verified successfully using the public key.
*/
JWS.prototype.verifyJWSByKey = function (jws, key) { return undefined; };

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
JWS.prototype.getUnparsedHeader = function () { return undefined; };

/**
Process a JSON Web Signature without verifying it. Call this before JWS.prototype.verifyJWSByKey if you need access to the header or data in the signature before verifying it. For example, the metadata might identify the issuer such that you can retrieve the appropriate public key.

@param {String} jws The JSON Web Signature to process.
*/
JWS.prototype.processJWS = function (jws) { return undefined; };
