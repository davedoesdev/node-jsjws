/*global RSAKey: false,
         KJUR: false,
         X509: false */
/*jslint node: true */

var ursa = require('ursa');

module.exports = Object.create(ursa);
module.exports.ursa = ursa;
module.exports.SlowRSAKey = RSAKey;
module.exports.JWS = KJUR.jws.JWS;
module.exports.JWT = KJUR.jws.JWT;
module.exports.X509 = X509;
