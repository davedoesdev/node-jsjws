/*jslint node: true */
"use strict";

var KJUR;

var navigator = {
  appName: "Netscape"
};

function alert(s)
{
  throw new Error(s);
}

var jsonParse = JSON.parse;
var crypto = require('crypto');

function SecureRandom()
{
    return undefined;
}

SecureRandom.prototype.nextBytes = function (ba)
{
    var rb = crypto.randomBytes(ba.length), i;

    for (i = 0; i < ba.length; i += 1)
    {
        ba[i] = rb[i];
    }
};

var YAHOO = { lang: { extend: function () { return undefined; } } };
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// PKCS#1 (OAEP) mask generation function
function oaep_mgf1_arr(seed, len, hash)
{
    var mask = '', i = 0;

    while (mask.length < len)
    {
        mask += hash(String.fromCharCode.apply(String, seed.concat([
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff])));
        i += 1;
    }

    return mask;
}

// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
function oaep_pad(s, n, hash, hashLen)
{
    if (!hash)
    {
        hash = rstr_sha1;
        hashLen = 20;
    }

    if (s.length + 2 * hashLen + 2 > n)
    {
        throw "Message too long for RSA";
    }

    var PS = '', i;

    for (i = 0; i < n - s.length - 2 * hashLen - 2; i += 1)
    {
        PS += '\x00';
    }

    var DB = hash('') + PS + '\x01' + s;
    var seed = new Array(hashLen);
    new SecureRandom().nextBytes(seed);
    
    var dbMask = oaep_mgf1_arr(seed, DB.length, hash);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1)
    {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var seedMask = oaep_mgf1_arr(maskedDB, seed.length, hash);
    var maskedSeed = [0];

    for (i = 0; i < seed.length; i += 1)
    {
        maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
    }

    return new BigInteger(maskedSeed.concat(maskedDB));
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N,E) {
  this.isPublic = true;
  if (typeof N !== "string") 
  {
    this.n = N;
    this.e = E;
  }
  else if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 OAEP RSA encryption of "text" as an even-length hex string
function RSAEncryptOAEP(text, hash, hashLen) {
  var m = oaep_pad(text, (this.n.bitLength()+7)>>3, hash, hashLen);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

RSAKey.prototype.type = "RSA";
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Depends on rsa.js and jsbn2.js

// Version 1.1: support utf-8 decoding in pkcs1unpad2

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d,n) {
  var b = d.toByteArray();
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2)
    return null;
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    if(c < 128) { // utf-8 decode
      ret += String.fromCharCode(c);
    }
    else if((c > 191) && (c < 224)) {
      ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
      ++i;
    }
    else {
      ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
      i += 2;
    }
  }
  return ret;
}

// PKCS#1 (OAEP) mask generation function
function oaep_mgf1_str(seed, len, hash)
{
    var mask = '', i = 0;

    while (mask.length < len)
    {
        mask += hash(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]));
        i += 1;
    }

    return mask;
}

// Undo PKCS#1 (OAEP) padding and, if valid, return the plaintext
function oaep_unpad(d, n, hash, hashLen)
{
    if (!hash)
    {
        hash = rstr_sha1;
        hashLen = 20;
    }

    d = d.toByteArray();

    var i;

    for (i = 0; i < d.length; i += 1)
    {
        d[i] &= 0xff;
    }

    while (d.length < n)
    {
        d.unshift(0);
    }

    d = String.fromCharCode.apply(String, d);

    if (d.length < 2 * hashLen + 2)
    {
        throw "Cipher too short";
    }

    var maskedSeed = d.substr(1, hashLen)
    var maskedDB = d.substr(hashLen + 1);

    var seedMask = oaep_mgf1_str(maskedDB, hashLen, hash);
    var seed = [], i;

    for (i = 0; i < maskedSeed.length; i += 1)
    {
        seed[i] = maskedSeed.charCodeAt(i) ^ seedMask.charCodeAt(i);
    }

    var dbMask = oaep_mgf1_str(String.fromCharCode.apply(String, seed),
                           d.length - hashLen, hash);

    var DB = [];

    for (i = 0; i < maskedDB.length; i += 1)
    {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB = String.fromCharCode.apply(String, DB);

    if (DB.substr(0, hashLen) !== hash(''))
    {
        throw "Hash mismatch";
    }

    DB = DB.substr(hashLen);

    var first_one = DB.indexOf('\x01');
    var last_zero = (first_one != -1) ? DB.substr(0, first_one).lastIndexOf('\x00') : -1;

    if (last_zero + 1 != first_one)
    {
        throw "Malformed data";
    }

    return DB.substr(first_one + 1);
}

// Set the private key fields N, e, and d from hex strings
function RSASetPrivate(N,E,D) {
  this.isPrivate = true;
  if (typeof N !== "string")
  {
    this.n = N;
    this.e = E;
    this.d = D;
  }
  else if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
  }
  else
    alert("Invalid RSA private key");
}

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
  this.isPrivate = true;
  if (N == null) throw "RSASetPrivateEx N == null";
  if (E == null) throw "RSASetPrivateEx E == null";
  if (N.length == 0) throw "RSASetPrivateEx N.length == 0";
  if (E.length == 0) throw "RSASetPrivateEx E.length == 0";

  if (N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
    this.d = parseBigInt(D,16);
    this.p = parseBigInt(P,16);
    this.q = parseBigInt(Q,16);
    this.dmp1 = parseBigInt(DP,16);
    this.dmq1 = parseBigInt(DQ,16);
    this.coeff = parseBigInt(C,16);
  } else {
    alert("Invalid RSA private key in RSASetPrivateEx");
  }
}

// Generate a new random private key B bits long, using public expt E
function RSAGenerate(B,E) {
  var rng = new SecureRandom();
  var qs = B>>1;
  this.e = parseInt(E,16);
  var ee = new BigInteger(E,16);
  for(;;) {
    for(;;) {
      this.p = new BigInteger(B-qs,1,rng);
      if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
    }
    for(;;) {
      this.q = new BigInteger(qs,1,rng);
      if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
    }
    if(this.p.compareTo(this.q) <= 0) {
      var t = this.p;
      this.p = this.q;
      this.q = t;
    }
    var p1 = this.p.subtract(BigInteger.ONE);	// p1 = p - 1
    var q1 = this.q.subtract(BigInteger.ONE);	// q1 = q - 1
    var phi = p1.multiply(q1);
    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);	// this.n = p * q
      this.d = ee.modInverse(phi);	// this.d = 
      this.dmp1 = this.d.mod(p1);	// this.dmp1 = d mod (p - 1)
      this.dmq1 = this.d.mod(q1);	// this.dmq1 = d mod (q - 1)
      this.coeff = this.q.modInverse(this.p);	// this.coeff = (q ^ -1) mod p
      break;
    }
  }
  this.isPrivate = true;
}

// Perform raw private operation on "x": return x^d (mod n)
function RSADoPrivate(x) {
  if(this.p == null || this.q == null)
    return x.modPow(this.d, this.n);

  // TODO: re-calculate any missing CRT params
  var xp = x.mod(this.p).modPow(this.dmp1, this.p); // xp=cp?
  var xq = x.mod(this.q).modPow(this.dmq1, this.q); // xq=cq?

  while(xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
  // NOTE:
  // xp.subtract(xq) => cp -cq
  // xp.subtract(xq).multiply(this.coeff).mod(this.p) => (cp - cq) * u mod p = h
  // xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq) => cq + (h * q) = M
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}

// Return the PKCS#1 OAEP RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecryptOAEP(ctext, hash, hashLen) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return oaep_unpad(m, (this.n.bitLength()+7)>>3, hash, hashLen);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is a Base64-encoded string and the output is a plain string.
//function RSAB64Decrypt(ctext) {
//  var h = b64tohex(ctext);
//  if(h) return this.decrypt(h); else return null;
//}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
RSAKey.prototype.decryptOAEP = RSADecryptOAEP;
//RSAKey.prototype.b64_decrypt = RSAB64Decrypt;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  if (b64pad) while((ret.length & 3) > 0) ret += b64pad;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  var v;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
/*! CryptoJS v3.1.2 core-fix.js
 * code.google.com/p/crypto-js
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 * code.google.com/p/crypto-js/wiki/License
 * THIS IS FIX of 'core.js' to fix Hmac issue.
 * https://code.google.com/p/crypto-js/issues/detail?id=84
 * https://crypto-js.googlecode.com/svn-history/r667/branches/3.x/src/core.js
 */
/**
 * CryptoJS core components.
 */
var CryptoJS = CryptoJS || (function (Math, undefined) {
    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var Base = C_lib.Base = (function () {
        function F() {}

        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
             */
            extend: function (overrides) {
                // Spawn
                F.prototype = this;
                var subtype = new F();

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Create default initializer
                if (!subtype.hasOwnProperty('init')) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                // Initializer's prototype is the subtype object
                subtype.init.prototype = subtype;

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var instance = MyType.create();
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
             */
            init: function () {
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             *
             * @example
             *
             *     MyType.mixIn({
             *         field: 'value'
             *     });
             */
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = instance.clone();
             */
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var WordArray = C_lib.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clamp excess bits
            this.clamp();

            // Concat
            if (thisSigBytes % 4) {
                // Copy one byte at a time
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else {
                // Copy one word at a time
                for (var i = 0; i < thatSigBytes; i += 4) {
                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                }
            }
            this.sigBytes += thatSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        random: function (nBytes) {
            var words = [];
            for (var i = 0; i < nBytes; i += 4) {
                words.push((Math.random() * 0x100000000) | 0);
            }

            return new WordArray.init(words, nBytes);
        }
    });

    /**
     * Encoder namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    /**
     * Abstract buffered block algorithm template.
     *
     * The property blockSize must be implemented in a concrete subtype.
     *
     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
     */
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        reset: function () {
            // Initial values
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */
        _append: function (data) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            // Append
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */
        _process: function (doFlush) {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            // Count blocks ready
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                // Round up to include partial blocks
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            // Count words ready
            var nWordsReady = nBlocksReady * blockSize;

            // Count bytes ready
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            // Process blocks
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                }

                // Remove processed words
                var processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            // Return processed words
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * Abstract hasher template.
     *
     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
     */
    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         */
        cfg: Base.extend(),

        /**
         * Initializes a newly created hasher.
         *
         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
         *
         * @example
         *
         *     var hasher = CryptoJS.algo.SHA256.create();
         */
        init: function (cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Set initial values
            this.reset();
        },

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-hasher logic
            this._doReset();
        },

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */
        update: function (messageUpdate) {
            // Append
            this._append(messageUpdate);

            // Update the hash
            this._process();

            // Chainable
            return this;
        },

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            // Perform concrete-hasher logic
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} hasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} hasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}(Math));
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function (undefined) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var Base = C_lib.Base;
    var X32WordArray = C_lib.WordArray;

    /**
     * x64 namespace.
     */
    var C_x64 = C.x64 = {};

    /**
     * A 64-bit word.
     */
    var X64Word = C_x64.Word = Base.extend({
        /**
         * Initializes a newly created 64-bit word.
         *
         * @param {number} high The high 32 bits.
         * @param {number} low The low 32 bits.
         *
         * @example
         *
         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
         */
        init: function (high, low) {
            this.high = high;
            this.low = low;
        }

        /**
         * Bitwise NOTs this word.
         *
         * @return {X64Word} A new x64-Word object after negating.
         *
         * @example
         *
         *     var negated = x64Word.not();
         */
        // not: function () {
            // var high = ~this.high;
            // var low = ~this.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise ANDs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to AND with this word.
         *
         * @return {X64Word} A new x64-Word object after ANDing.
         *
         * @example
         *
         *     var anded = x64Word.and(anotherX64Word);
         */
        // and: function (word) {
            // var high = this.high & word.high;
            // var low = this.low & word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise ORs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to OR with this word.
         *
         * @return {X64Word} A new x64-Word object after ORing.
         *
         * @example
         *
         *     var ored = x64Word.or(anotherX64Word);
         */
        // or: function (word) {
            // var high = this.high | word.high;
            // var low = this.low | word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise XORs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to XOR with this word.
         *
         * @return {X64Word} A new x64-Word object after XORing.
         *
         * @example
         *
         *     var xored = x64Word.xor(anotherX64Word);
         */
        // xor: function (word) {
            // var high = this.high ^ word.high;
            // var low = this.low ^ word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Shifts this word n bits to the left.
         *
         * @param {number} n The number of bits to shift.
         *
         * @return {X64Word} A new x64-Word object after shifting.
         *
         * @example
         *
         *     var shifted = x64Word.shiftL(25);
         */
        // shiftL: function (n) {
            // if (n < 32) {
                // var high = (this.high << n) | (this.low >>> (32 - n));
                // var low = this.low << n;
            // } else {
                // var high = this.low << (n - 32);
                // var low = 0;
            // }

            // return X64Word.create(high, low);
        // },

        /**
         * Shifts this word n bits to the right.
         *
         * @param {number} n The number of bits to shift.
         *
         * @return {X64Word} A new x64-Word object after shifting.
         *
         * @example
         *
         *     var shifted = x64Word.shiftR(7);
         */
        // shiftR: function (n) {
            // if (n < 32) {
                // var low = (this.low >>> n) | (this.high << (32 - n));
                // var high = this.high >>> n;
            // } else {
                // var low = this.high >>> (n - 32);
                // var high = 0;
            // }

            // return X64Word.create(high, low);
        // },

        /**
         * Rotates this word n bits to the left.
         *
         * @param {number} n The number of bits to rotate.
         *
         * @return {X64Word} A new x64-Word object after rotating.
         *
         * @example
         *
         *     var rotated = x64Word.rotL(25);
         */
        // rotL: function (n) {
            // return this.shiftL(n).or(this.shiftR(64 - n));
        // },

        /**
         * Rotates this word n bits to the right.
         *
         * @param {number} n The number of bits to rotate.
         *
         * @return {X64Word} A new x64-Word object after rotating.
         *
         * @example
         *
         *     var rotated = x64Word.rotR(7);
         */
        // rotR: function (n) {
            // return this.shiftR(n).or(this.shiftL(64 - n));
        // },

        /**
         * Adds this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to add with this word.
         *
         * @return {X64Word} A new x64-Word object after adding.
         *
         * @example
         *
         *     var added = x64Word.add(anotherX64Word);
         */
        // add: function (word) {
            // var low = (this.low + word.low) | 0;
            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
            // var high = (this.high + word.high + carry) | 0;

            // return X64Word.create(high, low);
        // }
    });

    /**
     * An array of 64-bit words.
     *
     * @property {Array} words The array of CryptoJS.x64.Word objects.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var X64WordArray = C_x64.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.x64.WordArray.create();
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ]);
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ], 10);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 8;
            }
        },

        /**
         * Converts this 64-bit word array to a 32-bit word array.
         *
         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
         *
         * @example
         *
         *     var x32WordArray = x64WordArray.toX32();
         */
        toX32: function () {
            // Shortcuts
            var x64Words = this.words;
            var x64WordsLength = x64Words.length;

            // Convert
            var x32Words = [];
            for (var i = 0; i < x64WordsLength; i++) {
                var x64Word = x64Words[i];
                x32Words.push(x64Word.high);
                x32Words.push(x64Word.low);
            }

            return X32WordArray.create(x32Words, this.sigBytes);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {X64WordArray} The clone.
         *
         * @example
         *
         *     var clone = x64WordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);

            // Clone "words" array
            var words = clone.words = this.words.slice(0);

            // Clone each X64Word object
            var wordsLength = words.length;
            for (var i = 0; i < wordsLength; i++) {
                words[i] = words[i].clone();
            }

            return clone;
        }
    });
}());
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function (Math) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var Hasher = C_lib.Hasher;
    var C_algo = C.algo;

    // Initialization and round constants tables
    var H = [];
    var K = [];

    // Compute constants
    (function () {
        function isPrime(n) {
            var sqrtN = Math.sqrt(n);
            for (var factor = 2; factor <= sqrtN; factor++) {
                if (!(n % factor)) {
                    return false;
                }
            }

            return true;
        }

        function getFractionalBits(n) {
            return ((n - (n | 0)) * 0x100000000) | 0;
        }

        var n = 2;
        var nPrime = 0;
        while (nPrime < 64) {
            if (isPrime(n)) {
                if (nPrime < 8) {
                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
                }
                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

                nPrime++;
            }

            n++;
        }
    }());

    // Reusable object
    var W = [];

    /**
     * SHA-256 hash algorithm.
     */
    var SHA256 = C_algo.SHA256 = Hasher.extend({
        _doReset: function () {
            this._hash = new WordArray.init(H.slice(0));
        },

        _doProcessBlock: function (M, offset) {
            // Shortcut
            var H = this._hash.words;

            // Working variables
            var a = H[0];
            var b = H[1];
            var c = H[2];
            var d = H[3];
            var e = H[4];
            var f = H[5];
            var g = H[6];
            var h = H[7];

            // Computation
            for (var i = 0; i < 64; i++) {
                if (i < 16) {
                    W[i] = M[offset + i] | 0;
                } else {
                    var gamma0x = W[i - 15];
                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
                                   (gamma0x >>> 3);

                    var gamma1x = W[i - 2];
                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
                                   (gamma1x >>> 10);

                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                }

                var ch  = (e & f) ^ (~e & g);
                var maj = (a & b) ^ (a & c) ^ (b & c);

                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

                var t1 = h + sigma1 + ch + K[i] + W[i];
                var t2 = sigma0 + maj;

                h = g;
                g = f;
                f = e;
                e = (d + t1) | 0;
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;
            }

            // Intermediate hash value
            H[0] = (H[0] + a) | 0;
            H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0;
            H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0;
            H[5] = (H[5] + f) | 0;
            H[6] = (H[6] + g) | 0;
            H[7] = (H[7] + h) | 0;
        },

        _doFinalize: function () {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            // Add padding
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
            data.sigBytes = dataWords.length * 4;

            // Hash final blocks
            this._process();

            // Return final computed hash
            return this._hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        }
    });

    /**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.SHA256('message');
     *     var hash = CryptoJS.SHA256(wordArray);
     */
    C.SHA256 = Hasher._createHelper(SHA256);

    /**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacSHA256(message, key);
     */
    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
}(Math));
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var Hasher = C_lib.Hasher;
    var C_x64 = C.x64;
    var X64Word = C_x64.Word;
    var X64WordArray = C_x64.WordArray;
    var C_algo = C.algo;

    function X64Word_create() {
        return X64Word.create.apply(X64Word, arguments);
    }

    // Constants
    var K = [
        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
    ];

    // Reusable objects
    var W = [];
    (function () {
        for (var i = 0; i < 80; i++) {
            W[i] = X64Word_create();
        }
    }());

    /**
     * SHA-512 hash algorithm.
     */
    var SHA512 = C_algo.SHA512 = Hasher.extend({
        _doReset: function () {
            this._hash = new X64WordArray.init([
                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
            ]);
        },

        _doProcessBlock: function (M, offset) {
            // Shortcuts
            var H = this._hash.words;

            var H0 = H[0];
            var H1 = H[1];
            var H2 = H[2];
            var H3 = H[3];
            var H4 = H[4];
            var H5 = H[5];
            var H6 = H[6];
            var H7 = H[7];

            var H0h = H0.high;
            var H0l = H0.low;
            var H1h = H1.high;
            var H1l = H1.low;
            var H2h = H2.high;
            var H2l = H2.low;
            var H3h = H3.high;
            var H3l = H3.low;
            var H4h = H4.high;
            var H4l = H4.low;
            var H5h = H5.high;
            var H5l = H5.low;
            var H6h = H6.high;
            var H6l = H6.low;
            var H7h = H7.high;
            var H7l = H7.low;

            // Working variables
            var ah = H0h;
            var al = H0l;
            var bh = H1h;
            var bl = H1l;
            var ch = H2h;
            var cl = H2l;
            var dh = H3h;
            var dl = H3l;
            var eh = H4h;
            var el = H4l;
            var fh = H5h;
            var fl = H5l;
            var gh = H6h;
            var gl = H6l;
            var hh = H7h;
            var hl = H7l;

            // Rounds
            for (var i = 0; i < 80; i++) {
                // Shortcut
                var Wi = W[i];

                // Extend message
                if (i < 16) {
                    var Wih = Wi.high = M[offset + i * 2]     | 0;
                    var Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
                } else {
                    // Gamma0
                    var gamma0x  = W[i - 15];
                    var gamma0xh = gamma0x.high;
                    var gamma0xl = gamma0x.low;
                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

                    // Gamma1
                    var gamma1x  = W[i - 2];
                    var gamma1xh = gamma1x.high;
                    var gamma1xl = gamma1x.low;
                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
                    var Wi7  = W[i - 7];
                    var Wi7h = Wi7.high;
                    var Wi7l = Wi7.low;

                    var Wi16  = W[i - 16];
                    var Wi16h = Wi16.high;
                    var Wi16l = Wi16.low;

                    var Wil = gamma0l + Wi7l;
                    var Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
                    var Wil = Wil + gamma1l;
                    var Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
                    var Wil = Wil + Wi16l;
                    var Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

                    Wi.high = Wih;
                    Wi.low  = Wil;
                }

                var chh  = (eh & fh) ^ (~eh & gh);
                var chl  = (el & fl) ^ (~el & gl);
                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

                // t1 = h + sigma1 + ch + K[i] + W[i]
                var Ki  = K[i];
                var Kih = Ki.high;
                var Kil = Ki.low;

                var t1l = hl + sigma1l;
                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
                var t1l = t1l + chl;
                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
                var t1l = t1l + Kil;
                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
                var t1l = t1l + Wil;
                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

                // t2 = sigma0 + maj
                var t2l = sigma0l + majl;
                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

                // Update working variables
                hh = gh;
                hl = gl;
                gh = fh;
                gl = fl;
                fh = eh;
                fl = el;
                el = (dl + t1l) | 0;
                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
                dh = ch;
                dl = cl;
                ch = bh;
                cl = bl;
                bh = ah;
                bl = al;
                al = (t1l + t2l) | 0;
                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
            }

            // Intermediate hash value
            H0l = H0.low  = (H0l + al);
            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
            H1l = H1.low  = (H1l + bl);
            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
            H2l = H2.low  = (H2l + cl);
            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
            H3l = H3.low  = (H3l + dl);
            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
            H4l = H4.low  = (H4l + el);
            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
            H5l = H5.low  = (H5l + fl);
            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
            H6l = H6.low  = (H6l + gl);
            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
            H7l = H7.low  = (H7l + hl);
            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
        },

        _doFinalize: function () {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            // Add padding
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
            data.sigBytes = dataWords.length * 4;

            // Hash final blocks
            this._process();

            // Convert hash to 32-bit word array before returning
            var hash = this._hash.toX32();

            // Return final computed hash
            return hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        },

        blockSize: 1024/32
    });

    /**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.SHA512('message');
     *     var hash = CryptoJS.SHA512(wordArray);
     */
    C.SHA512 = Hasher._createHelper(SHA512);

    /**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacSHA512(message, key);
     */
    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
}());
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var Base = C_lib.Base;
    var C_enc = C.enc;
    var Utf8 = C_enc.Utf8;
    var C_algo = C.algo;

    /**
     * HMAC algorithm.
     */
    var HMAC = C_algo.HMAC = Base.extend({
        /**
         * Initializes a newly created HMAC.
         *
         * @param {Hasher} hasher The hash algorithm to use.
         * @param {WordArray|string} key The secret key.
         *
         * @example
         *
         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
         */
        init: function (hasher, key) {
            // Init hasher
            hasher = this._hasher = new hasher.init();

            // Convert string to WordArray, else assume WordArray already
            if (typeof key == 'string') {
                key = Utf8.parse(key);
            }

            // Shortcuts
            var hasherBlockSize = hasher.blockSize;
            var hasherBlockSizeBytes = hasherBlockSize * 4;

            // Allow arbitrary length keys
            if (key.sigBytes > hasherBlockSizeBytes) {
                key = hasher.finalize(key);
            }

            // Clamp excess bits
            key.clamp();

            // Clone key for inner and outer pads
            var oKey = this._oKey = key.clone();
            var iKey = this._iKey = key.clone();

            // Shortcuts
            var oKeyWords = oKey.words;
            var iKeyWords = iKey.words;

            // XOR keys with pad constants
            for (var i = 0; i < hasherBlockSize; i++) {
                oKeyWords[i] ^= 0x5c5c5c5c;
                iKeyWords[i] ^= 0x36363636;
            }
            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

            // Set initial values
            this.reset();
        },

        /**
         * Resets this HMAC to its initial state.
         *
         * @example
         *
         *     hmacHasher.reset();
         */
        reset: function () {
            // Shortcut
            var hasher = this._hasher;

            // Reset
            hasher.reset();
            hasher.update(this._iKey);
        },

        /**
         * Updates this HMAC with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {HMAC} This HMAC instance.
         *
         * @example
         *
         *     hmacHasher.update('message');
         *     hmacHasher.update(wordArray);
         */
        update: function (messageUpdate) {
            this._hasher.update(messageUpdate);

            // Chainable
            return this;
        },

        /**
         * Finalizes the HMAC computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The HMAC.
         *
         * @example
         *
         *     var hmac = hmacHasher.finalize();
         *     var hmac = hmacHasher.finalize('message');
         *     var hmac = hmacHasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Shortcut
            var hasher = this._hasher;

            // Compute HMAC
            var innerHash = hasher.finalize(messageUpdate);
            hasher.reset();
            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

            return hmac;
        }
    });
}());
/*! asn1hex-1.1.6.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1hex.js - Hexadecimal represented ASN.1 string library
 *
 * Copyright (c) 2010-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1hex-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version asn1hex 1.1.6 (2015-Jun-11)
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/*
 * MEMO:
 *   f('3082025b02...', 2) ... 82025b ... 3bytes
 *   f('020100', 2) ... 01 ... 1byte
 *   f('0203001...', 2) ... 03 ... 1byte
 *   f('02818003...', 2) ... 8180 ... 2bytes
 *   f('3080....0000', 2) ... 80 ... -1
 *
 *   Requirements:
 *   - ASN.1 type octet length MUST be 1. 
 *     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
 */

/**
 * ASN.1 DER encoded hexadecimal string utility class
 * @name ASN1HEX
 * @class ASN.1 DER encoded hexadecimal string utility class
 * @since jsrsasign 1.1
 * @description
 * This class provides a parser for hexadecimal string of
 * DER encoded ASN.1 binary data.
 * Here are major methods of this class.
 * <ul>
 * <li><b>ACCESS BY POSITION</b>
 *   <ul>
 *   <li>{@link ASN1HEX.getHexOfTLV_AtObj} - get ASN.1 TLV at specified position</li>
 *   <li>{@link ASN1HEX.getHexOfV_AtObj} - get ASN.1 V at specified position</li>
 *   <li>{@link ASN1HEX.getHexOfL_AtObj} - get hexadecimal ASN.1 L at specified position</li>
 *   <li>{@link ASN1HEX.getIntOfL_AtObj} - get integer ASN.1 L at specified position</li>
 *   <li>{@link ASN1HEX.getStartPosOfV_AtObj} - get ASN.1 V position from its ASN.1 TLV position</li>
 *   </ul>
 * </li>
 * <li><b>ACCESS FOR CHILD ITEM</b>
 *   <ul>
 *   <li>{@link ASN1HEX.getNthChildIndex_AtObj} - get nth child index at specified position</li>
 *   <li>{@link ASN1HEX.getPosArrayOfChildren_AtObj} - get indexes of children</li>
 *   <li>{@link ASN1HEX.getPosOfNextSibling_AtObj} - get position of next sibling</li>
 *   </ul>
 * </li>
 * <li><b>ACCESS NESTED ASN.1 STRUCTURE</b>
 *   <ul>
 *   <li>{@link ASN1HEX.getDecendantHexTLVByNthList} - get ASN.1 TLV at specified list index</li>
 *   <li>{@link ASN1HEX.getDecendantHexVByNthList} - get ASN.1 V at specified list index</li>
 *   <li>{@link ASN1HEX.getDecendantIndexByNthList} - get index at specified list index</li>
 *   </ul>
 * </li>
 * <li><b>UTILITIES</b>
 *   <ul>
 *   <li>{@link ASN1HEX.dump} - dump ASN.1 structure</li>
 *   <li>{@link ASN1HEX.isASN1HEX} - check whether ASN.1 hexadecimal string or not</li>
 *   <li>{@link ASN1HEX.hextooidstr} - convert hexadecimal string of OID to dotted integer list</li>
 *   </ul>
 * </li>
 * </ul>
 */
var ASN1HEX = new function() {
    /**
     * get byte length for ASN.1 L(length) bytes
     * @name getByteLengthOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return byte length for ASN.1 L(length) bytes
     */
    this.getByteLengthOfL_AtObj = function(s, pos) {
        if (s.substring(pos + 2, pos + 3) != '8') return 1;
        var i = parseInt(s.substring(pos + 3, pos + 4));
        if (i == 0) return -1;          // length octet '80' indefinite length
        if (0 < i && i < 10) return i + 1;      // including '8?' octet;
        return -2;                              // malformed format
    };

    /**
     * get hexadecimal string for ASN.1 L(length) bytes
     * @name getHexOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return {String} hexadecimal string for ASN.1 L(length) bytes
     */
    this.getHexOfL_AtObj = function(s, pos) {
        var len = this.getByteLengthOfL_AtObj(s, pos);
        if (len < 1) return '';
        return s.substring(pos + 2, pos + 2 + len * 2);
    };

    //   getting ASN.1 length value at the position 'idx' of
    //   hexa decimal string 's'.
    //
    //   f('3082025b02...', 0) ... 82025b ... ???
    //   f('020100', 0) ... 01 ... 1
    //   f('0203001...', 0) ... 03 ... 3
    //   f('02818003...', 0) ... 8180 ... 128
    /**
     * get integer value of ASN.1 length for ASN.1 data
     * @name getIntOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return ASN.1 L(length) integer value
     */
    this.getIntOfL_AtObj = function(s, pos) {
        var hLength = this.getHexOfL_AtObj(s, pos);
        if (hLength == '') return -1;
        var bi;
        if (parseInt(hLength.substring(0, 1)) < 8) {
            bi = new BigInteger(hLength, 16);
        } else {
            bi = new BigInteger(hLength.substring(2), 16);
        }
        return bi.intValue();
    };

    /**
     * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
     * @name getStartPosOfV_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     */
    this.getStartPosOfV_AtObj = function(s, pos) {
        var l_len = this.getByteLengthOfL_AtObj(s, pos);
        if (l_len < 0) return l_len;
        return pos + (l_len + 1) * 2;
    };

    /**
     * get hexadecimal string of ASN.1 V(value)
     * @name getHexOfV_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return {String} hexadecimal string of ASN.1 value.
     */
    this.getHexOfV_AtObj = function(s, pos) {
        var pos1 = this.getStartPosOfV_AtObj(s, pos);
        var len = this.getIntOfL_AtObj(s, pos);
        return s.substring(pos1, pos1 + len * 2);
    };

    /**
     * get hexadecimal string of ASN.1 TLV at
     * @name getHexOfTLV_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return {String} hexadecimal string of ASN.1 TLV.
     * @since 1.1
     */
    this.getHexOfTLV_AtObj = function(s, pos) {
        var hT = s.substr(pos, 2);
        var hL = this.getHexOfL_AtObj(s, pos);
        var hV = this.getHexOfV_AtObj(s, pos);
        return hT + hL + hV;
    };

    /**
     * get next sibling starting index for ASN.1 object string
     * @name getPosOfNextSibling_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return next sibling starting index for ASN.1 object string
     */
    this.getPosOfNextSibling_AtObj = function(s, pos) {
        var pos1 = this.getStartPosOfV_AtObj(s, pos);
        var len = this.getIntOfL_AtObj(s, pos);
        return pos1 + len * 2;
    };

    /**
     * get array of indexes of child ASN.1 objects
     * @name getPosArrayOfChildren_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} start string index of ASN.1 object
     * @return {Array of Number} array of indexes for childen of ASN.1 objects
     */
    this.getPosArrayOfChildren_AtObj = function(h, pos) {
        var a = new Array();
        var p0 = this.getStartPosOfV_AtObj(h, pos);
        a.push(p0);

        var len = this.getIntOfL_AtObj(h, pos);
        var p = p0;
        var k = 0;
        while (1) {
            var pNext = this.getPosOfNextSibling_AtObj(h, p);
            if (pNext == null || (pNext - p0  >= (len * 2))) break;
            if (k >= 200) break;
            
            a.push(pNext);
            p = pNext;
            
            k++;
        }
        
        return a;
    };

    /**
     * get string index of nth child object of ASN.1 object refered by h, idx
     * @name getNthChildIndex_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} h hexadecimal string of ASN.1 DER encoded data
     * @param {Number} idx start string index of ASN.1 object
     * @param {Number} nth for child
     * @return {Number} string index of nth child.
     * @since 1.1
     */
    this.getNthChildIndex_AtObj = function(h, idx, nth) {
        var a = this.getPosArrayOfChildren_AtObj(h, idx);
        return a[nth];
    };

    // ========== decendant methods ==============================
    /**
     * get string index of nth child object of ASN.1 object refered by h, idx
     * @name getDecendantIndexByNthList
     * @memberOf ASN1HEX
     * @function
     * @param {String} h hexadecimal string of ASN.1 DER encoded data
     * @param {Number} currentIndex start string index of ASN.1 object
     * @param {Array of Number} nthList array list of nth
     * @return {Number} string index refered by nthList
     * @since 1.1
     * @example
     * The "nthList" is a index list of structured ASN.1 object
     * reference. Here is a sample structure and "nthList"s which
     * refers each objects.
     *
     * SQUENCE               - 
     *   SEQUENCE            - [0]
     *     IA5STRING 000     - [0, 0]
     *     UTF8STRING 001    - [0, 1]
     *   SET                 - [1]
     *     IA5STRING 010     - [1, 0]
     *     UTF8STRING 011    - [1, 1]
     */
    this.getDecendantIndexByNthList = function(h, currentIndex, nthList) {
        if (nthList.length == 0) {
            return currentIndex;
        }
        var firstNth = nthList.shift();
        var a = this.getPosArrayOfChildren_AtObj(h, currentIndex);
        return this.getDecendantIndexByNthList(h, a[firstNth], nthList);
    };

    /**
     * get hexadecimal string of ASN.1 TLV refered by current index and nth index list.
     * @name getDecendantHexTLVByNthList
     * @memberOf ASN1HEX
     * @function
     * @param {String} h hexadecimal string of ASN.1 DER encoded data
     * @param {Number} currentIndex start string index of ASN.1 object
     * @param {Array of Number} nthList array list of nth
     * @return {Number} hexadecimal string of ASN.1 TLV refered by nthList
     * @since 1.1
     */
    this.getDecendantHexTLVByNthList = function(h, currentIndex, nthList) {
        var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
        return this.getHexOfTLV_AtObj(h, idx);
    };

    /**
     * get hexadecimal string of ASN.1 V refered by current index and nth index list.
     * @name getDecendantHexVByNthList
     * @memberOf ASN1HEX
     * @function
     * @param {String} h hexadecimal string of ASN.1 DER encoded data
     * @param {Number} currentIndex start string index of ASN.1 object
     * @param {Array of Number} nthList array list of nth
     * @return {Number} hexadecimal string of ASN.1 V refered by nthList
     * @since 1.1
     */
    this.getDecendantHexVByNthList = function(h, currentIndex, nthList) {
        var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
        return this.getHexOfV_AtObj(h, idx);
    };
};

/*
 * @since asn1hex 1.1.4
 */
ASN1HEX.getVbyList = function(h, currentIndex, nthList, checkingTag) {
    var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
    if (idx === undefined) {
        throw "can't find nthList object";
    }
    if (checkingTag !== undefined) {
        if (h.substr(idx, 2) != checkingTag) {
            throw "checking tag doesn't match: " + 
                h.substr(idx,2) + "!=" + checkingTag;
        }
    }
    return this.getHexOfV_AtObj(h, idx);
};

/**
 * get OID string from hexadecimal encoded value
 * @name hextooidstr
 * @memberOf ASN1HEX
 * @function
 * @param {String} hex hexadecmal string of ASN.1 DER encoded OID value
 * @return {String} OID string (ex. '1.2.3.4.567')
 * @since asn1hex 1.1.5
 */
ASN1HEX.hextooidstr = function(hex) {
    var zeroPadding = function(s, len) {
        if (s.length >= len) return s;
        return new Array(len - s.length + 1).join('0') + s;
    };

    var a = [];

    // a[0], a[1]
    var hex0 = hex.substr(0, 2);
    var i0 = parseInt(hex0, 16);
    a[0] = new String(Math.floor(i0 / 40));
    a[1] = new String(i0 % 40);

    // a[2]..a[n]
   var hex1 = hex.substr(2);
    var b = [];
    for (var i = 0; i < hex1.length / 2; i++) {
    b.push(parseInt(hex1.substr(i * 2, 2), 16));
    }
    var c = [];
    var cbin = "";
    for (var i = 0; i < b.length; i++) {
        if (b[i] & 0x80) {
            cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
        } else {
            cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
            c.push(new String(parseInt(cbin, 2)));
            cbin = "";
        }
    }

    var s = a.join(".");
    if (c.length > 0) s = s + "." + c.join(".");
    return s;
};

/**
 * get string of simple ASN.1 dump from hexadecimal ASN.1 data
 * @name dump
 * @memberOf ASN1HEX
 * @function
 * @param {String} hex hexadecmal string of ASN.1 data
 * @param {Array} associative array of flags for dump (OPTION)
 * @param {Number} idx string index for starting dump (OPTION)
 * @param {String} indent string (OPTION)
 * @return {String} string of simple ASN.1 dump
 * @since jsrsasign 4.8.3 asn1hex 1.1.6
 * @description
 * This method will get an ASN.1 dump from
 * hexadecmal string of ASN.1 DER encoded data.
 * Here are features:
 * <ul>
 * <li>ommit long hexadecimal string</li>
 * <li>dump encapsulated OCTET STRING (good for X.509v3 extensions)</li>
 * <li>structured/primitive context specific tag support (i.e. [0], [3] ...)</li>
 * <li>automatic decode for implicit primitive context specific tag 
 * (good for X.509v3 extension value)
 *   <ul>
 *   <li>if hex starts '68747470'(i.e. http) it is decoded as utf8 encoded string.</li>
 *   <li>if it is in 'subjectAltName' extension value and is '[2]'(dNSName) tag
 *   value will be encoded as utf8 string</li>
 *   <li>otherwise it shows as hexadecimal string</li>
 *   </ul>
 * </li>
 * </ul>
 * @example
 * // ASN.1 INTEGER
 * ASN1HEX.dump('0203012345')
 * &darr;
 * INTEGER 012345
 *
 * // ASN.1 Object Identifier
 * ASN1HEX.dump('06052b0e03021a')
 * &darr;
 * ObjectIdentifier sha1 (1 3 14 3 2 26)
 *
 * // ASN.1 SEQUENCE
 * ASN1HEX.dump('3006020101020102')
 * &darr;
 * SEQUENCE
 *   INTEGER 01
 *   INTEGER 02
 *
 * // ASN.1 DUMP FOR X.509 CERTIFICATE
 * ASN1HEX.dump(X509.pemToHex(certPEM))
 * &darr;
 * SEQUENCE
 *   SEQUENCE
 *     [0]
 *       INTEGER 02
 *     INTEGER 0c009310d206dbe337553580118ddc87
 *     SEQUENCE
 *       ObjectIdentifier SHA256withRSA (1 2 840 113549 1 1 11)
 *       NULL
 *     SEQUENCE
 *       SET
 *         SEQUENCE
 *           ObjectIdentifier countryName (2 5 4 6)
 *           PrintableString 'US'
 *             :
 */
ASN1HEX.dump = function(hex, flags, idx, indent) {
    var _skipLongHex = function(hex, limitNumOctet) {
	if (hex.length <= limitNumOctet * 2) {
	    return hex;
	} else {
	    var s = hex.substr(0, limitNumOctet) + 
		    "..(total " + hex.length / 2 + "bytes).." +
		    hex.substr(hex.length - limitNumOctet, limitNumOctet);
	    return s;
	};
    };

    if (flags === undefined) flags = { "ommit_long_octet": 32 };
    if (idx === undefined) idx = 0;
    if (indent === undefined) indent = "";
    var skipLongHex = flags.ommit_long_octet;

    if (hex.substr(idx, 2) == "01") {
	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
	if (v == "00") {
	    return indent + "BOOLEAN FALSE\n";
	} else {
	    return indent + "BOOLEAN TRUE\n";
	}
    }
    if (hex.substr(idx, 2) == "02") {
	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
	return indent + "INTEGER " + _skipLongHex(v, skipLongHex) + "\n";
    }
    if (hex.substr(idx, 2) == "03") {
	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
	return indent + "BITSTRING " + _skipLongHex(v, skipLongHex) + "\n";
    }
    if (hex.substr(idx, 2) == "04") {
	var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
	if (ASN1HEX.isASN1HEX(v)) {
	    var s = indent + "OCTETSTRING, encapsulates\n";
	    s = s + ASN1HEX.dump(v, flags, 0, indent + "  ");
	    return s;
	} else {
	    return indent + "OCTETSTRING " + _skipLongHex(v, skipLongHex) + "\n";
	}
    }
    if (hex.substr(idx, 2) == "05") {
	return indent + "NULL\n";
    }
    if (hex.substr(idx, 2) == "06") {
	var hV = ASN1HEX.getHexOfV_AtObj(hex, idx);
        var oidDot = KJUR.asn1.ASN1Util.oidHexToInt(hV);
        var oidName = KJUR.asn1.x509.OID.oid2name(oidDot);
	var oidSpc = oidDot.replace(/\./g, ' ');
        if (oidName != '') {
  	    return indent + "ObjectIdentifier " + oidName + " (" + oidSpc + ")\n";
	} else {
  	    return indent + "ObjectIdentifier (" + oidSpc + ")\n";
	}
    }
    if (hex.substr(idx, 2) == "0c") {
	return indent + "UTF8String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
    }
    if (hex.substr(idx, 2) == "13") {
	return indent + "PrintableString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
    }
    if (hex.substr(idx, 2) == "14") {
	return indent + "TeletexString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
    }
    if (hex.substr(idx, 2) == "16") {
	return indent + "IA5String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "'\n";
    }
    if (hex.substr(idx, 2) == "17") {
	return indent + "UTCTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "\n";
    }
    if (hex.substr(idx, 2) == "18") {
	return indent + "GeneralizedTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(hex, idx)) + "\n";
    }
    if (hex.substr(idx, 2) == "30") {
	if (hex.substr(idx, 4) == "3000") {
	    return indent + "SEQUENCE {}\n";
	}

	var s = indent + "SEQUENCE\n";
	var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);

	var flagsTemp = flags;
	
	if ((aIdx.length == 2 || aIdx.length == 3) &&
	    hex.substr(aIdx[0], 2) == "06" &&
	    hex.substr(aIdx[aIdx.length - 1], 2) == "04") { // supposed X.509v3 extension
	    var oidHex = ASN1HEX.getHexOfV_AtObj(hex, aIdx[0]);
	    var oidDot = KJUR.asn1.ASN1Util.oidHexToInt(oidHex);
	    var oidName = KJUR.asn1.x509.OID.oid2name(oidDot);

	    var flagsClone = JSON.parse(JSON.stringify(flags));
	    flagsClone.x509ExtName = oidName;
	    flagsTemp = flagsClone;
	}
	
	for (var i = 0; i < aIdx.length; i++) {
	    s = s + ASN1HEX.dump(hex, flagsTemp, aIdx[i], indent + "  ");
	}
	return s;
    }
    if (hex.substr(idx, 2) == "31") {
	var s = indent + "SET\n";
	var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);
	for (var i = 0; i < aIdx.length; i++) {
	    s = s + ASN1HEX.dump(hex, flags, aIdx[i], indent + "  ");
	}
	return s;
    }
    var tag = parseInt(hex.substr(idx, 2), 16);
    if ((tag & 128) != 0) { // context specific 
	var tagNumber = tag & 31;
	if ((tag & 32) != 0) { // structured tag
	    var s = indent + "[" + tagNumber + "]\n";
	    var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx);
	    for (var i = 0; i < aIdx.length; i++) {
		s = s + ASN1HEX.dump(hex, flags, aIdx[i], indent + "  ");
	    }
	    return s;
	} else { // primitive tag
	    var v = ASN1HEX.getHexOfV_AtObj(hex, idx);
	    if (v.substr(0, 8) == "68747470") { // http
		v = hextoutf8(v);
	    }
	    if (flags.x509ExtName === "subjectAltName" &&
		tagNumber == 2) {
		v = hextoutf8(v);
	    }
	    
	    var s = indent + "[" + tagNumber + "] " + v + "\n";
	    return s;
	}
    }
    return indent + "UNKNOWN(" + hex.substr(idx, 2) + ") " + ASN1HEX.getHexOfV_AtObj(hex, idx) + "\n";
};

/**
 * check wheather the string is ASN.1 hexadecimal string or not
 * @name isASN1HEX
 * @memberOf ASN1HEX
 * @function
 * @param {String} hex string to check whether it is hexadecmal string for ASN.1 DER or not
 * @return {Boolean} true if it is hexadecimal string of ASN.1 data otherwise false
 * @since jsrsasign 4.8.3 asn1hex 1.1.6
 * @description
 * This method checks wheather the argument 'hex' is a hexadecimal string of
 * ASN.1 data or not.
 * @example
 * ASN1HEX.isASN1HEX('0203012345') &rarr; true // PROPER ASN.1 INTEGER
 * ASN1HEX.isASN1HEX('0203012345ff') &rarr; false // TOO LONG VALUE
 * ASN1HEX.isASN1HEX('02030123') &rarr; false // TOO SHORT VALUE
 * ASN1HEX.isASN1HEX('fa3bcd') &rarr; false // WRONG FOR ASN.1
 */
ASN1HEX.isASN1HEX = function(hex) {
    if (hex.length % 2 == 1) return false;

    var intL = ASN1HEX.getIntOfL_AtObj(hex, 0);
    var tV = hex.substr(0, 2);
    var lV = ASN1HEX.getHexOfL_AtObj(hex, 0);
    var hVLength = hex.length - tV.length - lV.length;
    if (hVLength == intL * 2) return true;

    return false;
};
/*! base64x-1.1.6 (c) 2012-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * version: 1.1.6 (2015-Nov-11)
 *
 * Copyright (c) 2012-2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * DEPENDS ON:
 *   - base64.js - Tom Wu's Base64 library
 */

/**
 * @fileOverview
 * @name base64x-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version asn1 1.1.6 (2015-Nov-11)
 * @since jsrsasign 2.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * Base64URL and supplementary functions for Tom Wu's base64.js library.<br/>
 * This class is just provide information about global functions
 * defined in 'base64x.js'. The 'base64x.js' script file provides
 * global functions for converting following data each other.
 * <ul>
 * <li>(ASCII) String</li>
 * <li>UTF8 String including CJK, Latin and other characters</li>
 * <li>byte array</li>
 * <li>hexadecimal encoded String</li>
 * <li>Full URIComponent encoded String (such like "%69%94")</li>
 * <li>Base64 encoded String</li>
 * <li>Base64URL encoded String</li>
 * </ul>
 * All functions in 'base64x.js' are defined in {@link _global_} and not
 * in this class.
 * 
 * @class Base64URL and supplementary functions for Tom Wu's base64.js library
 * @author Kenji Urushima
 * @version 1.1 (07 May 2012)
 * @requires base64.js
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function Base64x() {
}

// ==== string / byte array ================================
/**
 * convert a string to an array of character codes
 * @param {String} s
 * @return {Array of Numbers} 
 */
function stoBA(s) {
    var a = new Array();
    for (var i = 0; i < s.length; i++) {
	a[i] = s.charCodeAt(i);
    }
    return a;
}

/**
 * convert an array of character codes to a string
 * @param {Array of Numbers} a array of character codes
 * @return {String} s
 */
function BAtos(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	s = s + String.fromCharCode(a[i]);
    }
    return s;
}

// ==== byte array / hex ================================
/**
 * convert an array of bytes(Number) to hexadecimal string.<br/>
 * @param {Array of Numbers} a array of bytes
 * @return {String} hexadecimal string
 */
function BAtohex(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	var hex1 = a[i].toString(16);
	if (hex1.length == 1) hex1 = "0" + hex1;
	s = s + hex1;
    }
    return s;
}

// ==== string / hex ================================
/**
 * convert a ASCII string to a hexadecimal string of ASCII codes.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} hexadecimal string
 */
function stohex(s) {
    return BAtohex(stoBA(s));
}

// ==== string / base64 ================================
/**
 * convert a ASCII string to a Base64 encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} Base64 encoded string
 */
function stob64(s) {
    return hex2b64(stohex(s));
}

// ==== string / base64url ================================
/**
 * convert a ASCII string to a Base64URL encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {s} s ASCII string
 * @return {String} Base64URL encoded string
 */
function stob64u(s) {
    return b64tob64u(hex2b64(stohex(s)));
}

/**
 * convert a Base64URL encoded string to a ASCII string.<br/>
 * NOTE: This can't be used for Base64URL encoded non ASCII characters.
 * @param {s} s Base64URL encoded string
 * @return {String} ASCII string
 */
function b64utos(s) {
    return BAtos(b64toBA(b64utob64(s)));
}

// ==== base64 / base64url ================================
/**
 * convert a Base64 encoded string to a Base64URL encoded string.<br/>
 * Example: "ab+c3f/==" &rarr; "ab-c3f_"
 * @param {String} s Base64 encoded string
 * @return {String} Base64URL encoded string
 */
function b64tob64u(s) {
    s = s.replace(/\=/g, "");
    s = s.replace(/\+/g, "-");
    s = s.replace(/\//g, "_");
    return s;
}

/**
 * convert a Base64URL encoded string to a Base64 encoded string.<br/>
 * Example: "ab-c3f_" &rarr; "ab+c3f/=="
 * @param {String} s Base64URL encoded string
 * @return {String} Base64 encoded string
 */
function b64utob64(s) {
    if (s.length % 4 == 2) s = s + "==";
    else if (s.length % 4 == 3) s = s + "=";
    s = s.replace(/-/g, "+");
    s = s.replace(/_/g, "/");
    return s;
}

// ==== hex / base64url ================================
/**
 * convert a hexadecimal string to a Base64URL encoded string.<br/>
 * @param {String} s hexadecimal string
 * @return {String} Base64URL encoded string
 * @description
 * convert a hexadecimal string to a Base64URL encoded string.
 * NOTE: If leading "0" is omitted and odd number length for
 * hexadecimal leading "0" is automatically added.
 */
function hextob64u(s) {
    if (s.length % 2 == 1) s = "0" + s;
    return b64tob64u(hex2b64(s));
}

/**
 * convert a Base64URL encoded string to a hexadecimal string.<br/>
 * @param {String} s Base64URL encoded string
 * @return {String} hexadecimal string
 */
function b64utohex(s) {
    return b64tohex(b64utob64(s));
}

var utf8tob64u, b64utoutf8;

if (typeof Buffer === 'function')
{
  utf8tob64u = function (s)
  {
    return b64tob64u(new Buffer(s, 'utf8').toString('base64'));
  };

  b64utoutf8 = function (s)
  {
    return new Buffer(b64utob64(s), 'base64').toString('utf8');
  };
}
else
{
// ==== utf8 / base64url ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64URL encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64URL encoded string
 * @since 1.1
 */
  utf8tob64u = function (s)
  {
    return hextob64u(uricmptohex(encodeURIComponentAll(s)));
  };

/**
 * convert a Base64URL encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {String} s Base64URL encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1
 */
  b64utoutf8 = function (s)
  {
    return decodeURIComponent(hextouricmp(b64utohex(s)));
  };
}

// ==== utf8 / base64url ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64 encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} Base64 encoded string
 * @since 1.1.1
 */
function utf8tob64(s) {
  return hex2b64(uricmptohex(encodeURIComponentAll(s)));
}

/**
 * convert a Base64 encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {String} s Base64 encoded string
 * @return {String} UTF-8 encoded string
 * @since 1.1.1
 */
function b64toutf8(s) {
  return decodeURIComponent(hextouricmp(b64tohex(s)));
}

// ==== utf8 / hex ================================
/**
 * convert a UTF-8 encoded string including CJK or Latin to a hexadecimal encoded string.<br/>
 * @param {String} s UTF-8 encoded string
 * @return {String} hexadecimal encoded string
 * @since 1.1.1
 */
function utf8tohex(s) {
  return uricmptohex(encodeURIComponentAll(s));
}

/**
 * convert a hexadecimal encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * Note that when input is improper hexadecimal string as UTF-8 string, this function returns
 * 'null'.
 * @param {String} s hexadecimal encoded string
 * @return {String} UTF-8 encoded string or null
 * @since 1.1.1
 */
function hextoutf8(s) {
  return decodeURIComponent(hextouricmp(s));
}

/**
 * convert a hexadecimal encoded string to raw string including non printable characters.<br/>
 * @param {String} s hexadecimal encoded string
 * @return {String} raw string
 * @since 1.1.2
 * @example
 * hextorstr("610061") &rarr; "a\x00a"
 */
function hextorstr(sHex) {
    var s = "";
    for (var i = 0; i < sHex.length - 1; i += 2) {
        s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16));
    }
    return s;
}

/**
 * convert a raw string including non printable characters to hexadecimal encoded string.<br/>
 * @param {String} s raw string
 * @return {String} hexadecimal encoded string
 * @since 1.1.2
 * @example
 * rstrtohex("a\x00a") &rarr; "610061"
 */
function rstrtohex(s) {
    var result = "";
    for (var i = 0; i < s.length; i++) {
        result += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
    }
    return result;
}

// ==== hex / b64nl =======================================

/*
 * since base64x 1.1.3
 */
function hextob64(s) {
    return hex2b64(s);
}

/*
 * since base64x 1.1.3
 */
function hextob64nl(s) {
    var b64 = hextob64(s);
    var b64nl = b64.replace(/(.{64})/g, "$1\r\n");
    b64nl = b64nl.replace(/\r\n$/, '');
    return b64nl;
}

/*
 * since base64x 1.1.3
 */
function b64nltohex(s) {
    var b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, '');
    var hex = b64tohex(b64);
    return hex;
} 

// ==== URIComponent / hex ================================
/**
 * convert a URLComponent string such like "%67%68" to a hexadecimal string.<br/>
 * @param {String} s URIComponent string such like "%67%68"
 * @return {String} hexadecimal string
 * @since 1.1
 */
function uricmptohex(s) {
  return s.replace(/%/g, "");
}

/**
 * convert a hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function hextouricmp(s) {
  return s.replace(/(..)/g, "%$1");
}

// ==== URIComponent ================================
/**
 * convert UTFa hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * Note that these "<code>0-9A-Za-z!'()*-._~</code>" characters will not
 * converted to "%xx" format by builtin 'encodeURIComponent()' function.
 * However this 'encodeURIComponentAll()' function will convert 
 * all of characters into "%xx" format.
 * @param {String} s hexadecimal string
 * @return {String} URIComponent string such like "%67%68"
 * @since 1.1
 */
function encodeURIComponentAll(u8) {
  var s = encodeURIComponent(u8);
  var s2 = "";
  for (var i = 0; i < s.length; i++) {
    if (s[i] == "%") {
      s2 = s2 + s.substr(i, 3);
      i = i + 2;
    } else {
      s2 = s2 + "%" + stohex(s[i]);
    }
  }
  return s2;
}

// ==== new lines ================================
/**
 * convert all DOS new line("\r\n") to UNIX new line("\n") in 
 * a String "s".
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toUnix(s) {
    s = s.replace(/\r\n/mg, "\n");
    return s;
}

/**
 * convert all UNIX new line("\r\n") to DOS new line("\n") in 
 * a String "s".
 * @param {String} s string 
 * @return {String} converted string
 */
function newline_toDos(s) {
    s = s.replace(/\r\n/mg, "\n");
    s = s.replace(/\n/mg, "\r\n");
    return s;
}

// ==== others ================================

/**
 * convert string of integer array to hexadecimal string.<br/>
 * @param {String} s string of integer array
 * @return {String} hexadecimal string
 * @since base64x 1.1.6 jsrsasign 5.0.2
 * @throws "malformed integer array string: *" for wrong input
 * @description
 * This function converts a string of JavaScript integer array to
 * a hexadecimal string. Each integer value shall be in a range 
 * from 0 to 255 otherwise it raise exception. Input string can
 * have extra space or newline string so that they will be ignored.
 * 
 * @example
 * intarystrtohex(" [123, 34, 101, 34, 58] ")
 * -> 7b2265223a (i.e. `{"e":` as string)
 */
function intarystrtohex(s) {
  s = s.replace(/^\s*\[\s*/, '');
  s = s.replace(/\s*\]\s*$/, '');
  s = s.replace(/\s*/g, '');
  try {
    var hex = s.split(/,/).map(function(element, index, array) {
      var i = parseInt(element);
      if (i < 0 || 255 < i) throw "integer not in range 0-255";
      var hI = ("00" + i.toString(16)).slice(-2);
      return hI;
    }).join('');
    return hex;
  } catch(ex) {
    throw "malformed integer array string: " + ex;
  }
}

/**
 * find index of string where two string differs
 * @param {String} s1 string to compare
 * @param {String} s2 string to compare
 * @return {Number} string index of where character differs. Return -1 if same.
 * @since jsrsasign 4.9.0 base64x 1.1.5
 * @example
 * strdiffidx("abcdefg", "abcd4fg") -> 4
 * strdiffidx("abcdefg", "abcdefg") -> -1
 * strdiffidx("abcdefg", "abcdef") -> 6
 * strdiffidx("abcdefgh", "abcdef") -> 6
 */
var strdiffidx = function(s1, s2) {
    var n = s1.length;
    if (s1.length > s2.length) n = s2.length;
    for (var i = 0; i < n; i++) {
	if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i;
    }
    if (s1.length != s2.length) return n;
    return -1; // same
};
/*! crypto-1.1.8.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * crypto.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name crypto-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1.8 (2016-Feb-28)
 * @since jsrsasign 2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
/**
 * kjur's cryptographic algorithm provider library name space
 * <p>
 * This namespace privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.crypto
 * @namespace
 */
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.Util
 * @class static object for cryptographic function utilities
 * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @property {Array} DEFAULTPROVIDER associative array of default provider name for each hash and signature algorithms
 * @description
 */
KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = {
	'sha1':      "3021300906052b0e03021a05000414",
        'sha224':    "302d300d06096086480165030402040500041c",
	'sha256':    "3031300d060960864801650304020105000420",
	'sha384':    "3041300d060960864801650304020205000430",
	'sha512':    "3051300d060960864801650304020305000440",
	'md2':       "3020300c06082a864886f70d020205000410",
	'md5':       "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414",
    };

    /*
     * @since crypto 1.1.1
     */
    this.DEFAULTPROVIDER = {
	'md5':			'cryptojs',
	'sha1':			'cryptojs',
	'sha224':		'cryptojs',
	'sha256':		'cryptojs',
	'sha384':		'cryptojs',
	'sha512':		'cryptojs',
	'ripemd160':		'cryptojs',
	'hmacmd5':		'cryptojs',
	'hmacsha1':		'cryptojs',
	'hmacsha224':		'cryptojs',
	'hmacsha256':		'cryptojs',
	'hmacsha384':		'cryptojs',
	'hmacsha512':		'cryptojs',
	'hmacripemd160':	'cryptojs',

	'MD5withRSA':		'cryptojs/jsrsa',
	'SHA1withRSA':		'cryptojs/jsrsa',
	'SHA224withRSA':	'cryptojs/jsrsa',
	'SHA256withRSA':	'cryptojs/jsrsa',
	'SHA384withRSA':	'cryptojs/jsrsa',
	'SHA512withRSA':	'cryptojs/jsrsa',
	'RIPEMD160withRSA':	'cryptojs/jsrsa',

	'MD5withECDSA':		'cryptojs/jsrsa',
	'SHA1withECDSA':	'cryptojs/jsrsa',
	'SHA224withECDSA':	'cryptojs/jsrsa',
	'SHA256withECDSA':	'cryptojs/jsrsa',
	'SHA384withECDSA':	'cryptojs/jsrsa',
	'SHA512withECDSA':	'cryptojs/jsrsa',
	'RIPEMD160withECDSA':	'cryptojs/jsrsa',

	'SHA1withDSA':		'cryptojs/jsrsa',
	'SHA224withDSA':	'cryptojs/jsrsa',
	'SHA256withDSA':	'cryptojs/jsrsa',

	'MD5withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA1withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA224withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA256withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA384withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA512withRSAandMGF1':		'cryptojs/jsrsa',
	'RIPEMD160withRSAandMGF1':	'cryptojs/jsrsa',
    };

    /*
     * @since crypto 1.1.2
     */
    this.CRYPTOJSMESSAGEDIGESTNAME = {
	'md5':		CryptoJS.algo.MD5,
	'sha1':		CryptoJS.algo.SHA1,
	'sha224':	CryptoJS.algo.SHA224,
	'sha256':	CryptoJS.algo.SHA256,
	'sha384':	CryptoJS.algo.SHA384,
	'sha512':	CryptoJS.algo.SHA512,
	'ripemd160':	CryptoJS.algo.RIPEMD160
    };

    /**
     * get hexadecimal DigestInfo
     * @name getDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @return {String} hexadecimal string DigestInfo ASN.1 structure
     */
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    /**
     * get PKCS#1 padded hexadecimal DigestInfo
     * @name getPaddedDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value of message to be signed
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @param {Integer} keySize key bit length (ex. 1024)
     * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
     */
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	var hHead = "0001";
	var hTail = "00" + hDigestInfo;
	var hMid = "";
	var fLen = pmStrLen - hHead.length - hTail.length;
	for (var i = 0; i < fLen; i += 2) {
	    hMid += "ff";
	}
	var hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
    };

    /**
     * get hexadecimal hash of string with specified algorithm
     * @name hashString
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashString = function(s, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestString(s);
    };

    /**
     * get hexadecimal hash of hexadecimal string with specified algorithm
     * @name hashHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} sHex input hexadecimal string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashHex = function(sHex, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestHex(sHex);
    };

    /**
     * get hexadecimal SHA1 hash of string
     * @name sha1
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA256 hash of string
     * @name sha256
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha256Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal SHA512 hash of string
     * @name sha512
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha512Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal MD5 hash of string
     * @name md5
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.md5 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal RIPEMD160 hash of string
     * @name ripemd160
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.ripemd160 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /*
     * @since 1.1.2
     */
    this.getCryptoJSMDByName = function(s) {
	
    };
};

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class
 * @name KJUR.crypto.MessageDigest
 * @class MessageDigest class which is very similar to java.security.MessageDigest class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * var mdHex = md.digest()
 */
KJUR.crypto.MessageDigest = function(params) {
    var md = null;
    var algName = null;
    var provName = null;

    /**
     * set hash algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} alg hash algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
    this.setAlgAndProvider = function(alg, prov) {
	if (alg != null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg].create();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.md.update(wHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
	if (':sha256:'.indexOf(alg) != -1 &&
	    prov == 'sjcl') {
	    try {
		this.md = new sjcl.hash.sha256();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var baHex = sjcl.codec.hex.toBits(hex);
		this.md.update(baHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return sjcl.codec.hex.fromBits(hash);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * completes hash calculation and returns hash result
     * @name digest
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name digestString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @name digestHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.digestHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Mac(Message Authentication Code) class which is very similar to java.security.Mac class 
 * @name KJUR.crypto.Mac
 * @class Mac class which is very similar to java.security.Mac class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>hmacmd5 - cryptojs</li>
 * <li>hmacsha1 - cryptojs</li>
 * <li>hmacsha224 - cryptojs</li>
 * <li>hmacsha256 - cryptojs</li>
 * <li>hmacsha384 - cryptojs</li>
 * <li>hmacsha512 - cryptojs</li>
 * </ul>
 * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
 * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
 * to avoid those issue.
 * <br/>
 * NOTE2: Hmac signature bug was fixed in jsrsasign 4.9.0 by providing CryptoJS
 * bug workaround.
 * <br/>
 * Please see {@link KJUR.crypto.Mac.setPassword}, how to provide password
 * in various ways in detail.
 * @example
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA1", "pass": "pass"});
 * mac.updateString('aaa')
 * var macHex = md.doFinal()
 *
 * // other password representation 
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"hex":  "6161"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": "aa"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"rstr": "\x61\x61"}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64":  "Mi02/+...a=="}});
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64u": "Mi02_-...a"}});
 */
KJUR.crypto.Mac = function(params) {
    var mac = null;
    var pass = null;
    var algName = null;
    var provName = null;
    var algProv = null;

    this.setAlgAndProvider = function(alg, prov) {
	alg = alg.toLowerCase();

	if (alg == null) alg = "hmacsha1";

	alg = alg.toLowerCase();
        if (alg.substr(0, 4) != "hmac") {
	    throw "setAlgAndProvider unsupported HMAC alg: " + alg;
	}

	if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
	this.algProv = alg + "/" + prov;

	var hashAlg = alg.substr(4);

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		var mdObj = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
		this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.mac.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.mac.update(wHex);
	    };
	    this.doFinal = function() {
		var hash = this.mac.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.doFinalString = function(str) {
		this.updateString(str);
		return this.doFinal();
	    };
	    this.doFinalHex = function(hex) {
		this.updateHex(hex);
		return this.doFinal();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * completes hash calculation and returns hash result
     * @name doFinal
     * @memberOf KJUR.crypto.Mac
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.doFinal = function() {
	throw "digest() not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name doFinalString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.doFinalString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using hexadecimal string, 
     * then completes the digest computation
     * @name doFinalHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.doFinalHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * set password for Mac
     * @name setPassword
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {Object} pass password for Mac
     * @since crypto 1.1.7 jsrsasign 4.9.0
     * @description
     * This method will set password for (H)Mac internally.
     * Argument 'pass' can be specified as following:
     * <ul>
     * <li>even length string of 0..9, a..f or A-F: implicitly specified as hexadecimal string</li>
     * <li>not above string: implicitly specified as raw string</li>
     * <li>{rstr: "\x65\x70"}: explicitly specified as raw string</li>
     * <li>{hex: "6570"}: explicitly specified as hexacedimal string</li>
     * <li>{utf8: "秘密"}: explicitly specified as UTF8 string</li>
     * <li>{b64: "Mi78..=="}: explicitly specified as Base64 string</li>
     * <li>{b64u: "Mi7-_"}: explicitly specified as Base64URL string</li>
     * </ul>
     * It is *STRONGLY RECOMMENDED* that explicit representation of password argument
     * to avoid ambiguity. For example string  "6161" can mean a string "6161" or 
     * a hexadecimal string of "aa" (i.e. \x61\x61).
     * @example
     * mac = KJUR.crypto.Mac({'alg': 'hmacsha256'});
     * // set password by implicit raw string
     * mac.setPassword("\x65\x70\xb9\x0b");
     * mac.setPassword("password");
     * // set password by implicit hexadecimal string
     * mac.setPassword("6570b90b");
     * mac.setPassword("6570B90B");
     * // set password by explicit raw string
     * mac.setPassword({"rstr": "\x65\x70\xb9\x0b"});
     * // set password by explicit hexadecimal string
     * mac.setPassword({"hex": "6570b90b"});
     * // set password by explicit utf8 string
     * mac.setPassword({"utf8": "passwordパスワード");
     * // set password by explicit Base64 string
     * mac.setPassword({"b64": "Mb+c3f/=="});
     * // set password by explicit Base64URL string
     * mac.setPassword({"b64u": "Mb-c3f_"});
     */
    this.setPassword = function(pass) {
	// internal this.pass shall be CryptoJS DWord Object for CryptoJS bug
	// work around. CrytoJS HMac password can be passed by
	// raw string as described in the manual however it doesn't
	// work properly in some case. If password was passed
	// by CryptoJS DWord which is not described in the manual
	// it seems to work. (fixed since crypto 1.1.7)

	if (typeof pass == 'string') {
	    var hPass = pass;
	    if (pass.length % 2 == 1 || ! pass.match(/^[0-9A-Fa-f]+$/)) { // raw str
		hPass = rstrtohex(pass);
	    }
	    this.pass = CryptoJS.enc.Hex.parse(hPass);
	    return;
	}

	if (typeof pass != 'object')
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;
	
	var hPass = null;
	if (pass.hex  !== undefined) {
	    if (pass.hex.length % 2 != 0 || ! pass.hex.match(/^[0-9A-Fa-f]+$/))
		throw "Mac: wrong hex password: " + pass.hex;
	    hPass = pass.hex;
	}
	if (pass.utf8 !== undefined) hPass = utf8tohex(pass.utf8);
	if (pass.rstr !== undefined) hPass = rstrtohex(pass.rstr);
	if (pass.b64  !== undefined) hPass = b64tohex(pass.b64);
	if (pass.b64u !== undefined) hPass = b64utohex(pass.b64u);

	if (hPass == null)
	    throw "KJUR.crypto.Mac unsupported password type: " + pass;

	this.pass = CryptoJS.enc.Hex.parse(hPass);
    };

    if (params !== undefined) {
	if (params.pass !== undefined) {
	    this.setPassword(params.pass);
	}
	if (params.alg !== undefined) {
	    this.algName = params.alg;
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Signature class which is very similar to java.security.Signature class
 * @name KJUR.crypto.Signature
 * @class Signature class which is very similar to java.security.Signature class
 * @param {Array} params parameters for constructor
 * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * This Signature class supports following signature algorithm and provider names:
 * <ul>
 * <li>MD5withRSA - cryptojs/jsrsa</li>
 * <li>SHA1withRSA - cryptojs/jsrsa</li>
 * <li>SHA224withRSA - cryptojs/jsrsa</li>
 * <li>SHA256withRSA - cryptojs/jsrsa</li>
 * <li>SHA384withRSA - cryptojs/jsrsa</li>
 * <li>SHA512withRSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
 * <li>MD5withECDSA - cryptojs/jsrsa</li>
 * <li>SHA1withECDSA - cryptojs/jsrsa</li>
 * <li>SHA224withECDSA - cryptojs/jsrsa</li>
 * <li>SHA256withECDSA - cryptojs/jsrsa</li>
 * <li>SHA384withECDSA - cryptojs/jsrsa</li>
 * <li>SHA512withECDSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
 * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withDSA - cryptojs/jsrsa</li>
 * <li>SHA224withDSA - cryptojs/jsrsa</li>
 * <li>SHA256withDSA - cryptojs/jsrsa</li>
 * </ul>
 * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
 * <ul>
 * <li>secp256k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
 * <li>secp384r1, NIST P-384, P-384</li>
 * </ul>
 * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
 * <h4>EXAMPLES</h4>
 * @example
 * // RSA signature generation
 * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var hSigVal = sig.sign();
 *
 * // DSA signature validation
 * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
 * sig2.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig2.verify(hSigVal);
 * 
 * // ECDSA signing
 * var sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var sigValueHex = sig.sign();
 *
 * // ECDSA verifying
 * var sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig.verify(sigValueHex);
 */
KJUR.crypto.Signature = function(params) {
    var prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
    var pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

    var md = null; // KJUR.crypto.MessageDigest object
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
    var state = null;
    var pssSaltLen = -1;
    var initParams = null;

    var sHashHex = null; // hex hash value for hex
    var hDigestInfo = null;
    var hPaddedDigestInfo = null;
    var hSign = null;

    this._setAlgNames = function() {
	if (this.algName.match(/^(.+)with(.+)$/)) {
	    this.mdAlgName = RegExp.$1.toLowerCase();
	    this.pubkeyAlgName = RegExp.$2.toLowerCase();
	}
    };

    this._zeroPaddingOfSignature = function(hex, bitLength) {
	var s = "";
	var nZero = bitLength / 4 - hex.length;
	for (var i = 0; i < nZero; i++) {
	    s = s + "0";
	}
	return s + hex;
    };

    /**
     * set signature algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} alg signature algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
    this.setAlgAndProvider = function(alg, prov) {
	this._setAlgNames();
	if (prov != 'cryptojs/jsrsa')
	    throw "provider not supported: " + prov;

	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
	    try {
		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName});
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" +
                      this.mdAlgName + "/" + ex;
	    }

	    this.init = function(keyparam, pass) {
		var keyObj = null;
		try {
		    if (pass === undefined) {
			keyObj = KEYUTIL.getKey(keyparam);
		    } else {
			keyObj = KEYUTIL.getKey(keyparam, pass);
		    }
		} catch (ex) {
		    throw "init failed:" + ex;
		}

		if (keyObj.isPrivate === true) {
		    this.prvKey = keyObj;
		    this.state = "SIGN";
		} else if (keyObj.isPublic === true) {
		    this.pubKey = keyObj;
		    this.state = "VERIFY";
		} else {
		    throw "init failed.:" + keyObj;
		}
	    };

	    this.initSign = function(params) {
		if (typeof params['ecprvhex'] == 'string' &&
                    typeof params['eccurvename'] == 'string') {
		    this.ecprvhex = params['ecprvhex'];
		    this.eccurvename = params['eccurvename'];
		} else {
		    this.prvKey = params;
		}
		this.state = "SIGN";
	    };

	    this.initVerifyByPublicKey = function(params) {
		if (typeof params['ecpubhex'] == 'string' &&
		    typeof params['eccurvename'] == 'string') {
		    this.ecpubhex = params['ecpubhex'];
		    this.eccurvename = params['eccurvename'];
		} else if (params instanceof KJUR.crypto.ECDSA) {
		    this.pubKey = params;
		} else if (params instanceof RSAKey) {
		    this.pubKey = params;
		}
		this.state = "VERIFY";
	    };

	    this.initVerifyByCertificatePEM = function(certPEM) {
		var x509 = new X509();
		x509.readCertPEM(certPEM);
		this.pubKey = x509.subjectPublicKeyRSA;
		this.state = "VERIFY";
	    };

	    this.updateString = function(str) {
		this.md.updateString(str);
	    };

	    this.updateHex = function(hex) {
		this.md.updateHex(hex);
	    };

	    this.sign = function() {
		this.sHashHex = this.md.digest();
		if (typeof this.ecprvhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
		    this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
		} else if (this.prvKey instanceof RSAKey &&
		           this.pubkeyAlgName == "rsaandmgf1") {
		    this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
								    this.mdAlgName,
								    this.pssSaltLen);
		} else if (this.prvKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
								 this.mdAlgName);
		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
		return this.hSign;
	    };
	    this.signString = function(str) {
		this.updateString(str);
		return this.sign();
	    };
	    this.signHex = function(hex) {
		this.updateHex(hex);
		return this.sign();
	    };
	    this.verify = function(hSigVal) {
	        this.sHashHex = this.md.digest();
		if (typeof this.ecpubhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
		    var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
		    return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsaandmgf1") {
		    return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal, 
								this.mdAlgName,
								this.pssSaltLen);
		} else if (this.pubKey instanceof RSAKey &&
			   this.pubkeyAlgName == "rsa") {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.DSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
	    };
	}
    };

    /**
     * Initialize this object for signing or verifying depends on key
     * @name init
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
     * @param {String} pass (OPTION) passcode for encrypted private key
     * @since crypto 1.1.3
     * @description
     * This method is very useful initialize method for Signature class since
     * you just specify key then this method will automatically initialize it
     * using {@link KEYUTIL.getKey} method.
     * As for 'key',  following argument type are supported:
     * <h5>signing</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
     * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
     * <li>RSAKey object of private key</li>
     * <li>KJUR.crypto.ECDSA object of private key</li>
     * <li>KJUR.crypto.DSA object of private key</li>
     * </ul>
     * <h5>verification</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
     * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
     *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
     * <li>RSAKey object of public key</li>
     * <li>KJUR.crypto.ECDSA object of public key</li>
     * <li>KJUR.crypto.DSA object of public key</li>
     * </ul>
     * @example
     * sig.init(sCertPEM)
     */
    this.init = function(key, pass) {
	throw "init(key, pass) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a public key
     * @name initVerifyByPublicKey
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Public key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA verification</li>
     * <li>associative array for ECDSA verification
     *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
     * </li>
     * </ul>
     * @example
     * sig.initVerifyByPublicKey(rsaPrvKey)
     */
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a certficate
     * @name initVerifyByCertificatePEM
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} certPEM PEM formatted string of certificate
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * @example
     * sig.initVerifyByCertificatePEM(certPEM)
     */
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
	    this.algProvName;
    };

    /**
     * Initialize this object for signing
     * @name initSign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Private key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA signing</li>
     * <li>associative array for ECDSA signing
     *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
     * </ul>
     * @example
     * sig.initSign(prvKey)
     */
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a string
     * @name updateString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @name sign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.sign()
     */
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signString('aaa')
     */
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signHex('1fdc33')
     */
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * verifies the passed-in signature.
     * @name verify
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return {Boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * var isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
    this.verify = function(hSigVal) {
	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
    };

    this.initParams = params;

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined) {
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    } else {
		this.provName = params['prov'];
	    }
	    this.algProvName = this.algName + ":" + this.provName;
	    this.setAlgAndProvider(this.algName, this.provName);
	    this._setAlgNames();
	}

	if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

	if (params['prvkeypem'] !== undefined) {
	    if (params['prvkeypas'] !== undefined) {
		throw "both prvkeypem and prvkeypas parameters not supported";
	    } else {
		try {
		    var prvKey = new RSAKey();
		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
		    this.initSign(prvKey);
		} catch (ex) {
		    throw "fatal error to load pem private key: " + ex;
		}
	    }
	}
    }
};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.OID
 * @class static object for cryptography related OIDs
 * @property {Array} oidhex2name key value of hexadecimal OID and its name
 *           (ex. '2a8648ce3d030107' and 'secp256r1')
 * @since crypto 1.1.3
 * @description
 */


KJUR.crypto.OID = new function() {
    this.oidhex2name = {
	'2a864886f70d010101': 'rsaEncryption',
	'2a8648ce3d0201': 'ecPublicKey',
	'2a8648ce380401': 'dsa',
	'2a8648ce3d030107': 'secp256r1',
	'2b8104001f': 'secp192k1',
	'2b81040021': 'secp224r1',
	'2b8104000a': 'secp256k1',
	'2b81040023': 'secp521r1',
	'2b81040022': 'secp384r1',
	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
	'608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
    };
};
/*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * rsa-sign.js - adding signing functions to RSAKey class.
 *
 * version: 1.2.7 (2013 Aug 25)
 *
 * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name rsasign-1.2.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version rsasign 1.2.7
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
    var hashFunc = function(s) { return KJUR.crypto.Util.hashString(s, hashAlg); };
    var sHashHex = hashFunc(s);

    return KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, keySize);
}

function _zeroPaddingOfSignature(hex, bitLength) {
    var s = "";
    var nZero = bitLength / 4 - hex.length;
    for (var i = 0; i < nZero; i++) {
	s = s + "0";
    }
    return s + hex;
}

/**
 * sign for a message string with RSA private key.<br/>
 * @name signString
 * @memberOf RSAKey
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signString(s, hashAlg) {
    var hashFunc = function(s) { return KJUR.crypto.Util.hashString(s, hashAlg); };
    var sHashHex = hashFunc(s);

    return this.signWithMessageHash(sHashHex, hashAlg);
}

/**
 * sign hash value of message to be signed with RSA private key.<br/>
 * @name signWithMessageHash
 * @memberOf RSAKey
 * @function
 * @param {String} sHashHex hexadecimal string of hash value of message to be signed.
 * @param {String} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 * @since rsasign 1.2.6
 */
function _rsasign_signWithMessageHash(sHashHex, hashAlg) {
    var hPM = KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, this.n.bitLength());
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

function _rsasign_signStringWithSHA1(s) {
    return _rsasign_signString.call(this, s, 'sha1');
}

function _rsasign_signStringWithSHA256(s) {
    return _rsasign_signString.call(this, s, 'sha256');
}

// PKCS#1 (PSS) mask generation function
function pss_mgf1_str(seed, len, hash) {
    var mask = '', i = 0;

    while (mask.length < len) {
        mask += hextorstr(hash(rstrtohex(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]))));
        i += 1;
    }

    return mask;
}

/**
 * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
 * @name signStringPSS
 * @memberOf RSAKey
 * @function
 * @param {String} s message string to be signed.
 * @param {String} hashAlg hash algorithm name for signing.
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 */
function _rsasign_signStringPSS(s, hashAlg, sLen) {
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); } 
    var hHash = hashFunc(rstrtohex(s));

    if (sLen === undefined) sLen = -1;
    return this.signWithMessageHashPSS(hHash, hashAlg, sLen);
}

/**
 * sign hash value of message with RSA private key by PKCS#1 PSS signing.<br/>
 * @name signWithMessageHashPSS
 * @memberOf RSAKey
 * @function
 * @param {String} hHash hexadecimal hash value of message to be signed.
 * @param {String} hashAlg hash algorithm name for signing.
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 * @since rsasign 1.2.6
 */
function _rsasign_signWithMessageHashPSS(hHash, hashAlg, sLen) {
    var mHash = hextorstr(hHash);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); } 

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // maximum
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var salt = '';

    if (sLen > 0) {
        salt = new Array(sLen);
        new SecureRandom().nextBytes(salt);
        salt = String.fromCharCode.apply(String, salt);
    }

    var H = hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt)));
    var PS = [];

    for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
        PS[i] = 0x00;
    }

    var DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
    var dbMask = pss_mgf1_str(H, DB.length, hashFunc);
    var maskedDB = [];

    for (i = 0; i < DB.length; i += 1) {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
    maskedDB[0] &= ~mask;

    for (i = 0; i < hLen; i++) {
        maskedDB.push(H.charCodeAt(i));
    }

    maskedDB.push(0xbc);

    return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(maskedDB)).toString(16),
				   this.n.bitLength());
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
    var rsa = new RSAKey();
    rsa.setPublic(hN, hE);
    var biDecryptedSig = rsa.doPublic(biSig);
    return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
    var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
    for (var algName in KJUR.crypto.Util.DIGESTINFOHEAD) {
	var head = KJUR.crypto.Util.DIGESTINFOHEAD[algName];
	var len = head.length;
	if (hDigestInfo.substring(0, len) == head) {
	    var a = [algName, hDigestInfo.substring(len)];
	    return a;
	}
    }
    return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
    var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = function(s) { return KJUR.crypto.Util.hashString(s, algName); };
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
    var biSig = parseBigInt(hSig, 16);
    var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
						  this.n.toString(16),
						  this.e.toString(16));
    return result;
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyString
 * @memberOf RSAKey#
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
function _rsasign_verifyString(sMsg, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = function(s) { return KJUR.crypto.Util.hashString(s, algName); };
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @name verifyWithMessageHash
 * @memberOf RSAKey
 * @function
 * @param {String} sHashHex hexadecimal hash value of message to be verified.
 * @param {String} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 * @since rsasign 1.2.6
 */
function _rsasign_verifyWithMessageHash(sHashHex, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    return (diHashValue == sHashHex);
}

/**
 * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @name verifyStringPSS
 * @memberOf RSAKey
 * @function
 * @param {String} sMsg message string to be verified.
 * @param {String} hSig hexadecimal string of signature value
 * @param {String} hashAlg hash algorithm name
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 */
function _rsasign_verifyStringPSS(sMsg, hSig, hashAlg, sLen) {
    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); };
    var hHash = hashFunc(rstrtohex(sMsg));

    if (sLen === undefined) sLen = -1;
    return this.verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen);
}

/**
 * verifies a sigature for a hash value of message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @name verifyWithMessageHashPSS
 * @memberOf RSAKey
 * @function
 * @param {String} hHash hexadecimal hash value of message string to be verified.
 * @param {String} hSig hexadecimal string of signature value
 * @param {String} hashAlg hash algorithm name
 * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1 (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 * @since rsasign 1.2.6
 */
function _rsasign_verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen) {
    var biSig = new BigInteger(hSig, 16);

    if (biSig.bitLength() > this.n.bitLength()) {
        return false;
    }

    var hashFunc = function(sHex) { return KJUR.crypto.Util.hashHex(sHex, hashAlg); };
    var mHash = hextorstr(hHash);
    var hLen = mHash.length;
    var emBits = this.n.bitLength() - 1;
    var emLen = Math.ceil(emBits / 8);
    var i;

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // recover
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    var em = this.doPublic(biSig).toByteArray();

    for (i = 0; i < em.length; i += 1) {
        em[i] &= 0xff;
    }

    while (em.length < emLen) {
        em.unshift(0);
    }

    if (em[emLen -1] !== 0xbc) {
        throw "encoded message does not end in 0xbc";
    }

    em = String.fromCharCode.apply(String, em);

    var maskedDB = em.substr(0, emLen - hLen - 1);
    var H = em.substr(maskedDB.length, hLen);

    var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

    if ((maskedDB.charCodeAt(0) & mask) !== 0) {
        throw "bits beyond keysize not zero";
    }

    var dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
    var DB = [];

    for (i = 0; i < maskedDB.length; i += 1) {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB[0] &= ~mask;

    var checkLen = emLen - hLen - sLen - 2;

    for (i = 0; i < checkLen; i += 1) {
        if (DB[i] !== 0x00) {
            throw "leftmost octets not zero";
        }
    }

    if (DB[checkLen] !== 0x01) {
        throw "0x01 marker not found";
    }

    return H === hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
				     String.fromCharCode.apply(String, DB.slice(-sLen)))));
}

RSAKey.prototype.signWithMessageHash = _rsasign_signWithMessageHash;
RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;

RSAKey.prototype.signWithMessageHashPSS = _rsasign_signWithMessageHashPSS;
RSAKey.prototype.signStringPSS = _rsasign_signStringPSS;
RSAKey.prototype.signPSS = _rsasign_signStringPSS;
RSAKey.SALT_LEN_HLEN = -1;
RSAKey.SALT_LEN_MAX = -2;

RSAKey.prototype.verifyWithMessageHash = _rsasign_verifyWithMessageHash;
RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;

RSAKey.prototype.verifyWithMessageHashPSS = _rsasign_verifyWithMessageHashPSS;
RSAKey.prototype.verifyStringPSS = _rsasign_verifyStringPSS;
RSAKey.prototype.verifyPSS = _rsasign_verifyStringPSS;
RSAKey.SALT_LEN_RECOVER = -2;

/**
 * @name RSAKey
 * @class key of RSA public key algorithm
 * @description Tom Wu's RSA Key class and extension
 */
/*! keyutil-1.0.12.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * keyutil.js - key utility for PKCS#1/5/8 PEM, RSA/DSA/ECDSA key object
 *
 * Copyright (c) 2013-2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */
/**
 * @fileOverview
 * @name keyutil-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version keyutil 1.0.12 (2015-Oct-14)
 * @since jsrsasign 4.1.4
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * @name KEYUTIL
 * @class class for RSA/ECC/DSA key utility
 * @description 
 * <br/>
 * {@link KEYUTIL} class is an update of former {@link PKCS5PKEY} class.
 * So for now, {@link PKCS5PKEY} is deprecated class.
 * {@link KEYUTIL} class has following features:
 * <dl>
 * <dt><b>key loading - {@link KEYUTIL.getKey}</b>
 * <dd>
 * <ul>
 * <li>supports RSAKey and KJUR.crypto.{ECDSA,DSA} key object</li>
 * <li>supports private key and public key</li>
 * <li>supports encrypted and plain private key</li>
 * <li>supports PKCS#1, PKCS#5 and PKCS#8 key</li>
 * <li>supports public key in X.509 certificate</li>
 * <li>key represented by JSON object</li>
 * </ul>
 * NOTE1: Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES <br/>
 * NOTE2: Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC <br/>
 *
 * <dt><b>exporting key - {@link KEYUTIL.getPEM}</b>
 * <dd>
 * {@link KEYUTIL.getPEM} method supports following formats:
 * <ul>
 * <li>supports RSA/EC/DSA keys</li>
 * <li>PKCS#1 plain RSA/EC/DSA private key</li>
 * <li>PKCS#5 encrypted RSA/EC/DSA private key with DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>PKCS#8 plain RSA/EC/DSA private key</li>
 * <li>PKCS#8 encrypted RSA/EC/DSA private key with PBKDF2_HmacSHA1_3DES</li>
 * </ul>
 *
 * <dt><b>keypair generation - {@link KEYUTIL.generateKeypair}</b>
 * <ul>
 * <li>generate key pair of {@link RSAKey} or {@link KJUR.crypto.ECDSA}.</li>
 * <li>generate private key and convert it to PKCS#5 encrypted private key.</li>
 * </ul>
 * NOTE: {@link KJUR.crypto.DSA} is not yet supported.
 * </dl>
 * 
 * @example
 * // 1. loading PEM private key
 * var key = KEYUTIL.getKey(pemPKCS1PrivateKey);
 * var key = KEYUTIL.getKey(pemPKCS5EncryptedPrivateKey, "passcode");
 * var key = KEYUTIL.getKey(pemPKC85PlainPrivateKey);
 * var key = KEYUTIL.getKey(pemPKC85EncryptedPrivateKey, "passcode");
 * // 2. loading PEM public key
 * var key = KEYUTIL.getKey(pemPKCS8PublicKey);
 * var key = KEYUTIL.getKey(pemX509Certificate);
 * // 3. exporting private key
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS1PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode"); // DES-EDE3-CBC by default
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS5PRV", "passcode", "DES-CBC");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV");
 * var pem = KEYUTIL.getPEM(privateKeyObj, "PKCS8PRV", "passcode");
 * // 4. exporting public key
 * var pem = KEYUTIL.getPEM(publicKeyObj);
 */
/*
 * DEPRECATED METHODS
 * GET PKCS8
 * KEYUTIL.getRSAKeyFromPlainPKCS8PEM
 * KEYUTIL.getRSAKeyFromPlainPKCS8Hex
 * KEYUTIL.getRSAKeyFromEncryptedPKCS8PEM
 * P8 UTIL (make internal use)
 * KEYUTIL.getPlainPKCS8HexFromEncryptedPKCS8PEM
 * GET PKCS8 PUB
 * KEYUTIL.getKeyFromPublicPKCS8PEM
 * KEYUTIL.getKeyFromPublicPKCS8Hex
 * KEYUTIL.getRSAKeyFromPublicPKCS8PEM
 * KEYUTIL.getRSAKeyFromPublicPKCS8Hex
 * GET PKCS5
 * KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM
 * PUT PKCS5
 * KEYUTIL.getEncryptedPKCS5PEMFromRSAKey
 * OTHER METHODS (FOR INTERNAL?)
 * KEYUTIL.getHexFromPEM
 * KEYUTIL.getDecryptedKeyHexByKeyIV
 */
var KEYUTIL = function() {
    // *****************************************************************
    // *** PRIVATE PROPERTIES AND METHODS *******************************
    // *****************************************************************
    // shared key decryption ------------------------------------------
    var decryptAES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var decrypt3DES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var decryptDES = function(dataHex, keyHex, ivHex) {
        return decryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
    };

    var decryptGeneral = function(f, dataHex, keyHex, ivHex) {
        var data = CryptoJS.enc.Hex.parse(dataHex);
        var key = CryptoJS.enc.Hex.parse(keyHex);
        var iv = CryptoJS.enc.Hex.parse(ivHex);
        var encrypted = {};
        encrypted.key = key;
        encrypted.iv = iv;
        encrypted.ciphertext = data;
        var decrypted = f.decrypt(encrypted, key, { iv: iv });
        return CryptoJS.enc.Hex.stringify(decrypted);
    };

    // shared key decryption ------------------------------------------
    var encryptAES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.AES, dataHex, keyHex, ivHex);
    };

    var encrypt3DES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.TripleDES, dataHex, keyHex, ivHex);
    };

    var encryptDES = function(dataHex, keyHex, ivHex) {
        return encryptGeneral(CryptoJS.DES, dataHex, keyHex, ivHex);
    };

    var encryptGeneral = function(f, dataHex, keyHex, ivHex) {
        var data = CryptoJS.enc.Hex.parse(dataHex);
        var key = CryptoJS.enc.Hex.parse(keyHex);
        var iv = CryptoJS.enc.Hex.parse(ivHex);
        var encryptedHex = f.encrypt(data, key, { iv: iv });
        var encryptedWA = CryptoJS.enc.Hex.parse(encryptedHex.toString());
        var encryptedB64 = CryptoJS.enc.Base64.stringify(encryptedWA);
        return encryptedB64;
    };

    // other methods and properties ----------------------------------------
    var ALGLIST = {
        'AES-256-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 32, ivlen: 16 },
        'AES-192-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 24, ivlen: 16 },
        'AES-128-CBC':  { 'proc': decryptAES,  'eproc': encryptAES,  keylen: 16, ivlen: 16 },
        'DES-EDE3-CBC': { 'proc': decrypt3DES, 'eproc': encrypt3DES, keylen: 24, ivlen: 8 },
        'DES-CBC':      { 'proc': decryptDES,  'eproc': encryptDES,  keylen: 8,  ivlen: 8 }
    };

    var getFuncByName = function(algName) {
        return ALGLIST[algName]['proc'];
    };

    var _generateIvSaltHex = function(numBytes) {
        var wa = CryptoJS.lib.WordArray.random(numBytes);
        var hex = CryptoJS.enc.Hex.stringify(wa);
        return hex;
    };

    var _parsePKCS5PEM = function(sPKCS5PEM) {
        var info = {};
        if (sPKCS5PEM.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"))) {
            info.cipher = RegExp.$1;
            info.ivsalt = RegExp.$2;
        }
        if (sPKCS5PEM.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))) {
            info.type = RegExp.$1;
        }
        var i1 = -1;
        var lenNEWLINE = 0;
        if (sPKCS5PEM.indexOf("\r\n\r\n") != -1) {
            i1 = sPKCS5PEM.indexOf("\r\n\r\n");
            lenNEWLINE = 2;
        }
        if (sPKCS5PEM.indexOf("\n\n") != -1) {
            i1 = sPKCS5PEM.indexOf("\n\n");
            lenNEWLINE = 1;
        }
        var i2 = sPKCS5PEM.indexOf("-----END");
        if (i1 != -1 && i2 != -1) {
            var s = sPKCS5PEM.substring(i1 + lenNEWLINE * 2, i2 - lenNEWLINE);
            s = s.replace(/\s+/g, '');
            info.data = s;
        }
        return info;
    };

    var _getKeyAndUnusedIvByPasscodeAndIvsalt = function(algName, passcode, ivsaltHex) {
        //alert("ivsaltHex(2) = " + ivsaltHex);
        var saltHex = ivsaltHex.substring(0, 16);
        //alert("salt = " + saltHex);
        
        var salt = CryptoJS.enc.Hex.parse(saltHex);
        var data = CryptoJS.enc.Utf8.parse(passcode);
        //alert("salt = " + salt);
        //alert("data = " + data);

        var nRequiredBytes = ALGLIST[algName]['keylen'] + ALGLIST[algName]['ivlen'];
        var hHexValueJoined = '';
        var hLastValue = null;
        //alert("nRequiredBytes = " + nRequiredBytes);
        for (;;) {
            var h = CryptoJS.algo.MD5.create();
            if (hLastValue != null) {
                h.update(hLastValue);
            }
            h.update(data);
            h.update(salt);
            hLastValue = h.finalize();
            hHexValueJoined = hHexValueJoined + CryptoJS.enc.Hex.stringify(hLastValue);
            //alert("joined = " + hHexValueJoined);
            if (hHexValueJoined.length >= nRequiredBytes * 2) {
                break;
            }
        }
        var result = {};
        result.keyhex = hHexValueJoined.substr(0, ALGLIST[algName]['keylen'] * 2);
        result.ivhex = hHexValueJoined.substr(ALGLIST[algName]['keylen'] * 2, ALGLIST[algName]['ivlen'] * 2);
        return result;
    };

    /*
     * @param {String} privateKeyB64 base64 string of encrypted private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} hexadecimal string of decrypted private key
     */
    var _decryptKeyB64 = function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
        var privateKeyWA = CryptoJS.enc.Base64.parse(privateKeyB64);
        var privateKeyHex = CryptoJS.enc.Hex.stringify(privateKeyWA);
        var f = ALGLIST[sharedKeyAlgName]['proc'];
        var decryptedKeyHex = f(privateKeyHex, sharedKeyHex, ivsaltHex);
        return decryptedKeyHex;
    };
    
    /*
     * @param {String} privateKeyHex hexadecimal string of private key
     * @param {String} sharedKeyAlgName algorithm name of shared key encryption
     * @param {String} sharedKeyHex hexadecimal string of shared key to encrypt
     * @param {String} ivsaltHex hexadecimal string of IV and salt
     * @param {String} base64 string of encrypted private key
     */
    var _encryptKeyHex = function(privateKeyHex, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
        var f = ALGLIST[sharedKeyAlgName]['eproc'];
        var encryptedKeyB64 = f(privateKeyHex, sharedKeyHex, ivsaltHex);
        return encryptedKeyB64;
    };

    // *****************************************************************
    // *** PUBLIC PROPERTIES AND METHODS *******************************
    // *****************************************************************
    return {
        // -- UTILITY METHODS ------------------------------------------------------------
        /**
         * decrypt private key by shared key
         * @name version
         * @memberOf KEYUTIL
         * @property {String} version
         * @description version string of KEYUTIL class
         */
        version: "1.0.0",

        /**
         * get hexacedimal string of PEM format
         * @name getHexFromPEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sPEM PEM formatted string
         * @param {String} sHead PEM header string without BEGIN/END
         * @return {String} hexadecimal string data of PEM contents
         * @since pkcs5pkey 1.0.5
         */
        getHexFromPEM: function(sPEM, sHead) {
            var s = sPEM;
            if (s.indexOf("-----BEGIN ") == -1) {
                throw "can't find PEM header: " + sHead;
            }
            if (typeof sHead == "string" && sHead != "") {
                s = s.replace("-----BEGIN " + sHead + "-----", "");
                s = s.replace("-----END " + sHead + "-----", "");
            } else {
                s = s.replace(/-----BEGIN [^-]+-----/, '');
                s = s.replace(/-----END [^-]+-----/, '');
            }
            var sB64 = s.replace(/\s+/g, '');
            var dataHex = b64tohex(sB64);
            return dataHex;
        },

        /**
         * decrypt private key by shared key
         * @name getDecryptedKeyHexByKeyIV
         * @memberOf KEYUTIL
         * @function
         * @param {String} encryptedKeyHex hexadecimal string of encrypted private key
         * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
         * @param {String} sharedKeyHex hexadecimal string of symmetric key
         * @param {String} ivHex hexadecimal string of initial vector(IV).
         * @return {String} hexadecimal string of decrypted privated key
         */
        getDecryptedKeyHexByKeyIV: function(encryptedKeyHex, algName, sharedKeyHex, ivHex) {
            var f1 = getFuncByName(algName);
            return f1(encryptedKeyHex, sharedKeyHex, ivHex);
        },

        /**
         * parse PEM formatted passcode protected PKCS#5 private key
         * @name parsePKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>cipher - symmetric key algorithm name (ex. 'DES-EBE3-CBC', 'AES-256-CBC')</li>
         * <li>ivsalt - IV used for decrypt. Its heading 8 bytes will be used for passcode salt.</li>
         * <li>type - asymmetric key algorithm name of private key described in PEM header.</li>
         * <li>data - base64 encoded encrypted private key.</li>
         * </ul>
         *
         */
        parsePKCS5PEM: function(sPKCS5PEM) {
            return _parsePKCS5PEM(sPKCS5PEM);
        },

        /**
         * the same function as OpenSSL EVP_BytsToKey to generate shared key and IV
         * @name getKeyAndUnusedIvByPasscodeAndIvsalt
         * @memberOf KEYUTIL
         * @function
         * @param {String} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
         * @param {String} passcode passcode to decrypt private key (ex. 'password')
         * @param {String} hexadecimal string of IV. heading 8 bytes will be used for passcode salt
         * @return {Hash} hash of key and unused IV (ex. {keyhex:2fe3..., ivhex:3fad..})
         */
        getKeyAndUnusedIvByPasscodeAndIvsalt: function(algName, passcode, ivsaltHex) {
            return _getKeyAndUnusedIvByPasscodeAndIvsalt(algName, passcode, ivsaltHex);
        },

        decryptKeyB64: function(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
            return _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
        },

        /**
         * decrypt PEM formatted protected PKCS#5 private key with passcode
         * @name getDecryptedKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
         * @param {String} passcode passcode to decrypt private key (ex. 'password')
         * @return {String} hexadecimal string of decrypted RSA priavte key
         */
        getDecryptedKeyHex: function(sEncryptedPEM, passcode) {
            // 1. parse pem
            var info = _parsePKCS5PEM(sEncryptedPEM);
            var publicKeyAlgName = info.type;
            var sharedKeyAlgName = info.cipher;
            var ivsaltHex = info.ivsalt;
            var privateKeyB64 = info.data;
            //alert("ivsaltHex = " + ivsaltHex);

            // 2. generate shared key
            var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
            var sharedKeyHex = sharedKeyInfo.keyhex;
            //alert("sharedKeyHex = " + sharedKeyHex);

            // 3. decrypt private key
            var decryptedKey = _decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
            return decryptedKey;
        },

        /**
         * (DEPRECATED) read PEM formatted encrypted PKCS#5 private key and returns RSAKey object
         * @name getRSAKeyFromEncryptedPKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} sEncryptedP5PEM PEM formatted encrypted PKCS#5 private key
         * @param {String} passcode passcode to decrypt private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.2
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromEncryptedPKCS5PEM: function(sEncryptedP5PEM, passcode) {
            var hPKey = this.getDecryptedKeyHex(sEncryptedP5PEM, passcode);
            var rsaKey = new RSAKey();
            rsaKey.readPrivateKeyFromASN1HexString(hPKey);
            return rsaKey;
        },

        /*
         * get PEM formatted encrypted PKCS#5 private key from hexadecimal string of plain private key
         * @name getEncryptedPKCS5PEMFromPrvKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pemHeadAlg algorithm name in the pem header (i.e. RSA,EC or DSA)
         * @param {String} hPrvKey hexadecimal string of plain private key
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {String} sharedKeyAlgName algorithm name to protect private key (ex. AES-256-CBC)
         * @param {String} ivsaltHex hexadecimal string of IV and salt
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @description
         * <br/>
         * generate PEM formatted encrypted PKCS#5 private key by hexadecimal string encoded
         * ASN.1 object of plain RSA private key.
         * Following arguments can be omitted.
         * <ul>
         * <li>alg - AES-256-CBC will be used if omitted.</li>
         * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
         * </ul>
         * NOTE1: DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC algorithm are supported.
         * @example
         * var pem = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
         * var pem2 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
         * var pem3 = 
         *   KEYUTIL.getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
         */
        getEncryptedPKCS5PEMFromPrvKeyHex: function(pemHeadAlg, hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
            var sPEM = "";

            // 1. set sharedKeyAlgName if undefined (default AES-256-CBC)
            if (typeof sharedKeyAlgName == "undefined" || sharedKeyAlgName == null) {
                sharedKeyAlgName = "AES-256-CBC";
            }
            if (typeof ALGLIST[sharedKeyAlgName] == "undefined")
                throw "KEYUTIL unsupported algorithm: " + sharedKeyAlgName;

            // 2. set ivsaltHex if undefined
            if (typeof ivsaltHex == "undefined" || ivsaltHex == null) {
                var ivlen = ALGLIST[sharedKeyAlgName]['ivlen'];
                var randIV = _generateIvSaltHex(ivlen);
                ivsaltHex = randIV.toUpperCase();
            }

            // 3. get shared key
            //alert("ivsalthex=" + ivsaltHex);
            var sharedKeyInfo = _getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
            var sharedKeyHex = sharedKeyInfo.keyhex;
            // alert("sharedKeyHex = " + sharedKeyHex);

            // 3. get encrypted Key in Base64
            var encryptedKeyB64 = _encryptKeyHex(hPrvKey, sharedKeyAlgName, sharedKeyHex, ivsaltHex);

            var pemBody = encryptedKeyB64.replace(/(.{64})/g, "$1\r\n");
            var sPEM = "-----BEGIN " + pemHeadAlg + " PRIVATE KEY-----\r\n";
            sPEM += "Proc-Type: 4,ENCRYPTED\r\n";
            sPEM += "DEK-Info: " + sharedKeyAlgName + "," + ivsaltHex + "\r\n";
            sPEM += "\r\n";
            sPEM += pemBody;
            sPEM += "\r\n-----END " + pemHeadAlg + " PRIVATE KEY-----\r\n";

            return sPEM;
        },

        /**
         * (DEPRECATED) get PEM formatted encrypted PKCS#5 private key from RSAKey object of private key
         * @name getEncryptedPKCS5PEMFromRSAKey
         * @memberOf KEYUTIL
         * @function
         * @param {RSAKey} pKey RSAKey object of private key
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {String} alg algorithm name to protect private key (default AES-256-CBC)
         * @param {String} ivsaltHex hexadecimal string of IV and salt (default generated random IV)
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getPEM#}.
         * @description
         * <br/>
         * generate PEM formatted encrypted PKCS#5 private key by
         * {@link RSAKey} object of RSA private key and passcode.
         * Following argument can be omitted.
         * <ul>
         * <li>alg - AES-256-CBC will be used if omitted.</li>
         * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
         * </ul>
         * @example
         * var pkey = new RSAKey();
         * pkey.generate(1024, '10001'); // generate 1024bit RSA private key with public exponent 'x010001'
         * var pem = KEYUTIL.getEncryptedPKCS5PEMFromRSAKey(pkey, "password");
         */
        getEncryptedPKCS5PEMFromRSAKey: function(pKey, passcode, alg, ivsaltHex) {
            var version = new KJUR.asn1.DERInteger({'int': 0});
            var n = new KJUR.asn1.DERInteger({'bigint': pKey.n});
            var e = new KJUR.asn1.DERInteger({'int': pKey.e});
            var d = new KJUR.asn1.DERInteger({'bigint': pKey.d});
            var p = new KJUR.asn1.DERInteger({'bigint': pKey.p});
            var q = new KJUR.asn1.DERInteger({'bigint': pKey.q});
            var dmp1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmp1});
            var dmq1 = new KJUR.asn1.DERInteger({'bigint': pKey.dmq1});
            var coeff = new KJUR.asn1.DERInteger({'bigint': pKey.coeff});
            var seq = new KJUR.asn1.DERSequence({'array': [version, n, e, d, p, q, dmp1, dmq1, coeff]});
            var hex = seq.getEncodedHex();
            return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", hex, passcode, alg, ivsaltHex);
        },

        /**
         * generate RSAKey and PEM formatted encrypted PKCS#5 private key
         * @name newEncryptedPKCS5PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} passcode pass code to protect private key (ex. password)
         * @param {Integer} keyLen key bit length of RSA key to be generated. (default 1024)
         * @param {String} hPublicExponent hexadecimal string of public exponent (default 10001)
         * @param {String} alg shared key algorithm to encrypt private key (default AES-258-CBC)
         * @return {String} string of PEM formatted encrypted PKCS#5 private key
         * @since pkcs5pkey 1.0.2
         * @example
         * var pem1 = KEYUTIL.newEncryptedPKCS5PEM("password");           // RSA1024bit/10001/AES-256-CBC
         * var pem2 = KEYUTIL.newEncryptedPKCS5PEM("password", 512);      // RSA 512bit/10001/AES-256-CBC
         * var pem3 = KEYUTIL.newEncryptedPKCS5PEM("password", 512, '3'); // RSA 512bit/    3/AES-256-CBC
         */
        newEncryptedPKCS5PEM: function(passcode, keyLen, hPublicExponent, alg) {
            if (typeof keyLen == "undefined" || keyLen == null) {
                keyLen = 1024;
            }
            if (typeof hPublicExponent == "undefined" || hPublicExponent == null) {
                hPublicExponent = '10001';
            }
            var pKey = new RSAKey();
            pKey.generate(keyLen, hPublicExponent);
            var pem = null;
            if (typeof alg == "undefined" || alg == null) {
                pem = this.getEncryptedPKCS5PEMFromRSAKey(pKey, passcode);
            } else {
                pem = this.getEncryptedPKCS5PEMFromRSAKey(pKey, passcode, alg);
            }
            return pem;
        },

        // === PKCS8 ===============================================================

        /**
         * (DEPRECATED) read PEM formatted unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPlainPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted unencrypted PKCS#8 private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.1
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPlainPKCS8PEM: function(pkcs8PEM) {
            if (pkcs8PEM.match(/ENCRYPTED/))
                throw "pem shall be not ENCRYPTED";
            var prvKeyHex = this.getHexFromPEM(pkcs8PEM, "PRIVATE KEY");
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * (DEPRECATED) provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPlainPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} prvKeyHex hexadecimal string of unencrypted PKCS#8 private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPlainPKCS8Hex: function(prvKeyHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(prvKeyHex, 0);
            if (a1.length != 3)
                throw "outer DERSequence shall have 3 elements: " + a1.length;
            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + algIdTLV;
            var algIdTLV = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[1]);
            var octetStr = ASN1HEX.getHexOfTLV_AtObj(prvKeyHex, a1[2]);
            var p5KeyHex = ASN1HEX.getHexOfV_AtObj(octetStr, 0);
            //alert(p5KeyHex);
            var rsaKey = new RSAKey();
            rsaKey.readPrivateKeyFromASN1HexString(p5KeyHex);
            return rsaKey;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name parseHexOfEncryptedPKCS8
         * @memberOf KEYUTIL
         * @function
         * @param {String} passcode passcode to decrypto private key
         * @return {Array} info associative array of PKCS#8 parameters
         * @since pkcs5pkey 1.0.3
         * @description
         * The associative array which is returned by this method has following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * <li>info.ciphertext - hexadecimal string of encrypted private key</li>
         * <li>info.encryptionSchemeAlg - encryption algorithm name (currently TripleDES only)</li>
         * <li>info.encryptionSchemeIV - initial vector for encryption algorithm</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        parseHexOfEncryptedPKCS8: function(sHEX) {
            var info = {};
            
            var a0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, 0);
            if (a0.length != 2)
                throw "malformed format: SEQUENCE(0).items != 2: " + a0.length;

            // 1. ciphertext
            info.ciphertext = ASN1HEX.getHexOfV_AtObj(sHEX, a0[1]);

            // 2. pkcs5PBES2
            var a0_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0[0]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0).items != 2: " + a0_0.length;

            // 2.1 check if pkcs5PBES2(1 2 840 113549 1 5 13)
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0[0]) != "2a864886f70d01050d")
                throw "this only supports pkcs5PBES2";

            // 2.2 pkcs5PBES2 param
            var a0_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0[1]); 
            if (a0_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1).items != 2: " + a0_0_1.length;

            // 2.2.1 encryptionScheme
            var a0_0_1_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[1]); 
            if (a0_0_1_1.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + a0_0_1_1.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[0]) != "2a864886f70d0307")
                throw "this only supports TripleDES";
            info.encryptionSchemeAlg = "TripleDES";

            // 2.2.1.1 IV of encryptionScheme
            info.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_1[1]);

            // 2.2.2 keyDerivationFunc
            var a0_0_1_0 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1[0]); 
            if (a0_0_1_0.length != 2)
                throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + a0_0_1_0.length;
            if (ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0[0]) != "2a864886f70d01050c")
                throw "this only supports pkcs5PBKDF2";

            // 2.2.2.1 pkcs5PBKDF2 param
            var a0_0_1_0_1 = ASN1HEX.getPosArrayOfChildren_AtObj(sHEX, a0_0_1_0[1]); 
            if (a0_0_1_0_1.length < 2)
                throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + a0_0_1_0_1.length;

            // 2.2.2.1.1 PBKDF2 salt
            info.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[0]);

            // 2.2.2.1.2 PBKDF2 iter
            var iterNumHex = ASN1HEX.getHexOfV_AtObj(sHEX, a0_0_1_0_1[1]);
            try {
                info.pbkdf2Iter = parseInt(iterNumHex, 16);
            } catch(ex) {
                throw "malformed format pbkdf2Iter: " + iterNumHex;
            }

            return info;
        },

        /**
         * generate PBKDF2 key hexstring with specified passcode and information
         * @name getPBKDF2KeyHexFromParam
         * @memberOf KEYUTIL
         * @function
         * @param {Array} info result of {@link parseHexOfEncryptedPKCS8} which has preference of PKCS#8 file
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of PBKDF2 key
         * @since pkcs5pkey 1.0.3
         * @description
         * As for info, this uses following properties:
         * <ul>
         * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
         * <li>info.pkbdf2Iter - iteration count</li>
         * </ul>
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getPBKDF2KeyHexFromParam: function(info, passcode) {
            var pbkdf2SaltWS = CryptoJS.enc.Hex.parse(info.pbkdf2Salt);
            var pbkdf2Iter = info.pbkdf2Iter;
            var pbkdf2KeyWS = CryptoJS.PBKDF2(passcode, 
                                              pbkdf2SaltWS, 
                                              { keySize: 192/32, iterations: pbkdf2Iter });
            var pbkdf2KeyHex = CryptoJS.enc.Hex.stringify(pbkdf2KeyWS);
            return pbkdf2KeyHex;
        },

        /**
         * read PEM formatted encrypted PKCS#8 private key and returns hexadecimal string of plain PKCS#8 private key
         * @name getPlainPKCS8HexFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {String} hexadecimal string of plain PKCS#8 private key
         * @since pkcs5pkey 1.0.3
         * @description
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getPlainPKCS8HexFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            // 1. derHex - PKCS#8 private key encrypted by PBKDF2
            var derHex = this.getHexFromPEM(pkcs8PEM, "ENCRYPTED PRIVATE KEY");
            // 2. info - PKCS#5 PBES info
            var info = this.parseHexOfEncryptedPKCS8(derHex);
            // 3. hKey - PBKDF2 key
            var pbkdf2KeyHex = KEYUTIL.getPBKDF2KeyHexFromParam(info, passcode);
            // 4. decrypt ciphertext by PBKDF2 key
            var encrypted = {};
            encrypted.ciphertext = CryptoJS.enc.Hex.parse(info.ciphertext);
            var pbkdf2KeyWS = CryptoJS.enc.Hex.parse(pbkdf2KeyHex);
            var des3IVWS = CryptoJS.enc.Hex.parse(info.encryptionSchemeIV);
            var decWS = CryptoJS.TripleDES.decrypt(encrypted, pbkdf2KeyWS, { iv: des3IVWS });
            var decHex = CryptoJS.enc.Hex.stringify(decWS);
            return decHex;
        },

        /**
         * (DEPRECATED) read PEM formatted encrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM PEM formatted encrypted PKCS#8 private key
         * @param {String} passcode passcode to decrypto private key
         * @return {RSAKey} loaded RSAKey object of RSA private key
         * @since pkcs5pkey 1.0.3
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         * @description
         * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
         * <ul>
         * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
         * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
         * </ul>
         * @example
         * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
         * // key with PBKDF2 with TripleDES
         * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
         */
        getRSAKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var rsaKey = this.getRSAKeyFromPlainPKCS8Hex(prvKeyHex);
            return rsaKey;
        },

        /**
         * get RSAKey/ECDSA private key object from encrypted PEM PKCS#8 private key
         * @name getKeyFromEncryptedPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of PEM formatted PKCS#8 private key
         * @param {String} passcode passcode string to decrypt key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromEncryptedPKCS8PEM: function(pkcs8PEM, passcode) {
            var prvKeyHex = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 plain private key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
         * <li>keyidx - string starting index of key in pkcs8PrvHex</li>
         * </ul>
         */
        parsePlainPrivatePKCS8Hex: function(pkcs8PrvHex) {
            var result = {};
            result.algparam = null;

            // 1. sequence
            if (pkcs8PrvHex.substr(0, 2) != "30")
                throw "malformed plain PKCS8 private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, 0);
            if (a1.length != 3)
                throw "malformed plain PKCS8 private key(code:002)";

            // 2. AlgID
            if (pkcs8PrvHex.substr(a1[1], 2) != "30")
                throw "malformed PKCS8 private key(code:003)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, a1[1]);
            if (a2.length != 2)
                throw "malformed PKCS8 private key(code:004)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PrvHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 private key(code:005)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a2[1]);
            }

            // 3. Key index
            if (pkcs8PrvHex.substr(a1[2], 2) != "04")
                throw "malformed PKCS8 private key(code:006)"; // not octet string

            result.keyidx = ASN1HEX.getStartPosOfV_AtObj(pkcs8PrvHex, a1[2]);

            return result;
        },

        /**
         * get RSAKey/ECDSA private key object from PEM plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PEM string of plain PEM formatted PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8PEM: function(prvKeyPEM) {
            var prvKeyHex = this.getHexFromPEM(prvKeyPEM, "PRIVATE KEY");
            var key = this.getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
            return key;
        },

        /**
         * get RSAKey/ECDSA private key object from HEX plain PEM PKCS#8 private key
         * @name getKeyFromPlainPrivatePKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} prvKeyHex hexadecimal string of plain PKCS#8 private key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         */
        getKeyFromPlainPrivatePKCS8Hex: function(prvKeyHex) {
            var p8 = this.parsePlainPrivatePKCS8Hex(prvKeyHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                this.parsePrivateRawRSAKeyHexAtObj(prvKeyHex, p8);
                var k = p8.key;
                var key = new RSAKey();
                key.setPrivateEx(k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.co);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                this.parsePrivateRawECKeyHexAtObj(prvKeyHex, p8);
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName});
                key.setPublicKeyHex(p8.pubkey);
                key.setPrivateKeyHex(p8.key);
                key.isPublic = false;
                return key;
            } else if (p8.algoid == "2a8648ce380401") { // DSA
                var hP = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,0], "02");
                var hQ = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,1], "02");
                var hG = ASN1HEX.getVbyList(prvKeyHex, 0, [1,1,2], "02");
                var hX = ASN1HEX.getVbyList(prvKeyHex, 0, [2,0], "02");
                var biP = new BigInteger(hP, 16);
                var biQ = new BigInteger(hQ, 16);
                var biG = new BigInteger(hG, 16);
                var biX = new BigInteger(hX, 16);
                var key = new KJUR.crypto.DSA();
                key.setPrivate(biP, biQ, biG, null, biX);
                return key;
            } else {
                throw "unsupported private key algorithm";
            }
        },

        // === PKCS8 RSA Public Key ================================================
        /**
         * (DEPRECATED) read PEM formatted PKCS#8 public key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubPEM PEM formatted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var rsaKey = this.getRSAKeyFromPublicPKCS8Hex(pubKeyHex);
            return rsaKey;
        },

        /**
         * (DEPRECATED) get RSAKey/ECDSA public key object from PEM PKCS#8 public key
         * @name getKeyFromPublicPKCS8PEM
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcsPub8PEM string of PEM formatted PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.ECDSA private key object
         * @since pkcs5pkey 1.0.5
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getKeyFromPublicPKCS8PEM: function(pkcs8PubPEM) {
            var pubKeyHex = this.getHexFromPEM(pkcs8PubPEM, "PUBLIC KEY");
            var key = this.getKeyFromPublicPKCS8Hex(pubKeyHex);
            return key;
        },

        /**
         * (DEPRECATED) get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#8 public key
         * @name getKeyFromPublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcsPub8Hex hexadecimal string of PKCS#8 public key
         * @return {Object} RSAKey or KJUR.crypto.{ECDSA,DSA} private key object
         * @since pkcs5pkey 1.0.5
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var p8 = this.parsePublicPKCS8Hex(pkcs8PubHex);
            
            if (p8.algoid == "2a864886f70d010101") { // RSA
                var aRSA = this.parsePublicRawRSAKeyHex(p8.key);
                var key = new RSAKey();
                key.setPublic(aRSA.n, aRSA.e);
                return key;
            } else if (p8.algoid == "2a8648ce3d0201") { // ECC
                if (KJUR.crypto.OID.oidhex2name[p8.algparam] === undefined)
                    throw "KJUR.crypto.OID.oidhex2name undefined: " + p8.algparam;
                var curveName = KJUR.crypto.OID.oidhex2name[p8.algparam];
                var key = new KJUR.crypto.ECDSA({'curve': curveName, 'pub': p8.key});
                return key;
            } else if (p8.algoid == "2a8648ce380401") { // DSA 1.2.840.10040.4.1
                var param = p8.algparam;
                var y = ASN1HEX.getHexOfV_AtObj(p8.key, 0);
                var key = new KJUR.crypto.DSA();
                key.setPublic(new BigInteger(param.p, 16),
                              new BigInteger(param.q, 16),
                              new BigInteger(param.g, 16),
                              new BigInteger(y, 16));
                return key;
            } else {
                throw "unsupported public key algorithm";
            }
        },

        /**
         * parse hexadecimal string of plain PKCS#8 private key
         * @name parsePublicRawRSAKeyHex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pubRawRSAHex hexadecimal string of ASN.1 encoded PKCS#8 public key
         * @return {Array} associative array of parsed key
         * @since pkcs5pkey 1.0.5
         * @description
         * Resulted associative array has following properties:
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * </ul>
         */
        parsePublicRawRSAKeyHex: function(pubRawRSAHex) {
            var result = {};
            
            // 1. Sequence
            if (pubRawRSAHex.substr(0, 2) != "30")
                throw "malformed RSA key(code:001)"; // not sequence
            
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pubRawRSAHex, 0);
            if (a1.length != 2)
                throw "malformed RSA key(code:002)"; // not 2 items in seq

            // 2. public key "N"
            if (pubRawRSAHex.substr(a1[0], 2) != "02")
                throw "malformed RSA key(code:003)"; // 1st item is not integer

            result.n = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[0]);

            // 3. public key "E"
            if (pubRawRSAHex.substr(a1[1], 2) != "02")
                throw "malformed RSA key(code:004)"; // 2nd item is not integer

            result.e = ASN1HEX.getHexOfV_AtObj(pubRawRSAHex, a1[1]);

            return result;
        },

        /**
         * parse hexadecimal string of RSA private key
         * @name parsePrivateRawRSAKeyHexAtObj
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding RSA private key
         * @return {Array} info associative array to add parsed RSA private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>n - hexadecimal string of public key
         * <li>e - hexadecimal string of public exponent
         * <li>d - hexadecimal string of private key
         * <li>p - hexadecimal string
         * <li>q - hexadecimal string
         * <li>dp - hexadecimal string
         * <li>dq - hexadecimal string
         * <li>co - hexadecimal string
         * </ul>
         */
        parsePrivateRawRSAKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            // 1. sequence
            if (pkcs8PrvHex.substr(keyIdx, 2) != "30")
                throw "malformed RSA private key(code:001)"; // not sequence

            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PrvHex, keyIdx);
            if (a1.length != 9)
                throw "malformed RSA private key(code:002)"; // not sequence

            // 2. RSA key
            info.key = {};
            info.key.n = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[1]);
            info.key.e = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[2]);
            info.key.d = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[3]);
            info.key.p = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[4]);
            info.key.q = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[5]);
            info.key.dp = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[6]);
            info.key.dq = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[7]);
            info.key.co = ASN1HEX.getHexOfV_AtObj(pkcs8PrvHex, a1[8]);
        },

        /**
         * parse hexadecimal string of ECC private key
         * @name parsePrivateRawECKeyHexAtObj
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PrvHex hexadecimal string of PKCS#8 private key concluding EC private key
         * @return {Array} info associative array to add parsed ECC private key information
         * @since pkcs5pkey 1.0.5
         * @description
         * Following properties are added to associative array 'info'
         * <ul>
         * <li>key - hexadecimal string of ECC private key
         * </ul>
         */
        parsePrivateRawECKeyHexAtObj: function(pkcs8PrvHex, info) {
            var keyIdx = info.keyidx;
            
            var key = ASN1HEX.getVbyList(pkcs8PrvHex, keyIdx, [1], "04");
            var pubkey = ASN1HEX.getVbyList(pkcs8PrvHex, keyIdx, [2,0], "03").substr(2);

            info.key = key;
            info.pubkey = pubkey;
        },

        /**
         * parse hexadecimal string of PKCS#8 RSA/EC/DSA public key
         * @name parsePublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of PKCS#8 public key
         * @return {Hash} hash of key information
         * @description
         * Resulted hash has following attributes.
         * <ul>
         * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
         * <li>algparam - hexadecimal string of OID of ECC curve name, parameter SEQUENCE of DSA or null</li>
         * <li>key - hexadecimal string of public key</li>
         * </ul>
         */
        parsePublicPKCS8Hex: function(pkcs8PubHex) {
            var result = {};
            result.algparam = null;

            // 1. AlgID and Key bit string
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            // 2. AlgID
            var idxAlgIdTLV = a1[0];
            if (pkcs8PubHex.substr(idxAlgIdTLV, 2) != "30")
                throw "malformed PKCS8 public key(code:001)"; // AlgId not sequence

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxAlgIdTLV);
            if (a2.length != 2)
                throw "malformed PKCS8 public key(code:002)"; // AlgId not have two elements

            // 2.1. AlgID OID
            if (pkcs8PubHex.substr(a2[0], 2) != "06")
                throw "malformed PKCS8 public key(code:003)"; // AlgId.oid is not OID

            result.algoid = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);

            // 2.2. AlgID param
            if (pkcs8PubHex.substr(a2[1], 2) == "06") { // OID for EC
                result.algparam = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);
            } else if (pkcs8PubHex.substr(a2[1], 2) == "30") { // SEQ for DSA
                result.algparam = {};
                result.algparam.p = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [0], "02");
                result.algparam.q = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [1], "02");
                result.algparam.g = ASN1HEX.getVbyList(pkcs8PubHex, a2[1], [2], "02");
            }

            // 3. Key
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "malformed PKCS8 public key(code:004)"; // Key is not bit string

            result.key = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a1[1]).substr(2);
            
            // 4. return result assoc array
            return result;
        },

        /**
         * (DEPRECATED) provide hexadecimal string of unencrypted PKCS#8 private key and returns RSAKey object
         * @name getRSAKeyFromPublicPKCS8Hex
         * @memberOf KEYUTIL
         * @function
         * @param {String} pkcs8PubHex hexadecimal string of unencrypted PKCS#8 public key
         * @return {RSAKey} loaded RSAKey object of RSA public key
         * @since pkcs5pkey 1.0.4
         * @deprecated From jsrsasign 4.2.1 please use {@link KEYUTIL.getKey#}.
         */
        getRSAKeyFromPublicPKCS8Hex: function(pkcs8PubHex) {
            var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, 0);
            if (a1.length != 2)
                throw "outer DERSequence shall have 2 elements: " + a1.length;

            var algIdTLV =ASN1HEX.getHexOfTLV_AtObj(pkcs8PubHex, a1[0]);
            if (algIdTLV != "300d06092a864886f70d0101010500") // AlgId rsaEncryption
                throw "PKCS8 AlgorithmId is not rsaEncryption";
            
            if (pkcs8PubHex.substr(a1[1], 2) != "03")
                throw "PKCS8 Public Key is not BITSTRING encapslated.";

            var idxPub = ASN1HEX.getStartPosOfV_AtObj(pkcs8PubHex, a1[1]) + 2; // 2 for unused bit
            
            if (pkcs8PubHex.substr(idxPub, 2) != "30")
                throw "PKCS8 Public Key is not SEQUENCE.";

            var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(pkcs8PubHex, idxPub);
            if (a2.length != 2)
                throw "inner DERSequence shall have 2 elements: " + a2.length;

            if (pkcs8PubHex.substr(a2[0], 2) != "02") 
                throw "N is not ASN.1 INTEGER";
            if (pkcs8PubHex.substr(a2[1], 2) != "02") 
                throw "E is not ASN.1 INTEGER";
            
            var hN = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[0]);
            var hE = ASN1HEX.getHexOfV_AtObj(pkcs8PubHex, a2[1]);

            var pubKey = new RSAKey();
            pubKey.setPublic(hN, hE);
            
            return pubKey;
        },

        //addAlgorithm: function(functionObject, algName, keyLen, ivLen) {
        //}
    };
}();

// -- MAJOR PUBLIC METHODS -------------------------------------------------------
/**
 * get private or public key object from any arguments
 * @name getKey
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} param parameter to get key object. see description in detail.
 * @param {String} passcode (OPTION) parameter to get key object. see description in detail.
 * @param {String} hextype (OPTOIN) parameter to get key object. see description in detail.
 * @return {Object} {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.ECDSA} object
 * @since keyutil 1.0.0
 * @description
 * This method gets private or public key object({@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA})
 * for RSA, DSA and ECC.
 * Arguments for this methods depends on a key format you specify.
 * Following key representations are supported.
 * <ul>
 * <li>ECC private/public key object(as is): param=KJUR.crypto.ECDSA</li>
 * <li>DSA private/public key object(as is): param=KJUR.crypto.DSA</li>
 * <li>RSA private/public key object(as is): param=RSAKey </li>
 * <li>ECC private key parameters: param={d: d, curve: curveName}</li>
 * <li>RSA private key parameters: param={n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, co: co}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>DSA private key parameters: param={p: p, q: q, g: g, y: y, x: x}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>ECC public key parameters: param={xy: xy, curve: curveName}<br/>
 * NOTE: ECC public key 'xy' shall be concatination of "04", x-bytes-hex and y-bytes-hex.</li>
 * <li>DSA public key parameters: param={p: p, q: q, g: g, y: y}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>RSA public key parameters: param={n: n, e: e} </li>
 * <li>X.509v1/v3 PEM certificate (RSA/DSA/ECC): param=pemString</li>
 * <li>PKCS#8 hexadecimal RSA/ECC public key: param=pemString, null, "pkcs8pub"</li>
 * <li>PKCS#8 PEM RSA/DSA/ECC public key: param=pemString</li>
 * <li>PKCS#5 plain hexadecimal RSA private key: param=hexString, null, "pkcs5prv"</li>
 * <li>PKCS#5 plain PEM DSA/RSA private key: param=pemString</li>
 * <li>PKCS#8 plain PEM RSA/ECDSA private key: param=pemString</li>
 * <li>PKCS#5 encrypted PEM RSA/DSA private key: param=pemString, passcode</li>
 * <li>PKCS#8 encrypted PEM RSA/ECDSA private key: param=pemString, passcode</li>
 * </ul>
 * Please note following limitation on encrypted keys:
 * <ul>
 * <li>Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES</li>
 * <li>Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>JWT plain ECC private/public key</li>
 * <li>JWT plain RSA public key</li>
 * <li>JWT plain RSA private key with P/Q/DP/DQ/COEFF</li>
 * <li>JWT plain RSA private key without P/Q/DP/DQ/COEFF (since jsrsasign 5.0.0)</li>
 * </ul>
 * NOTE1: <a href="https://tools.ietf.org/html/rfc7517">RFC 7517 JSON Web Key(JWK)</a> support for RSA/ECC private/public key from jsrsasign 4.8.1.<br/>
 * NOTE2: X509v1 support is added since jsrsasign 5.0.11.
 * 
 * <h5>EXAMPLE</h5>
 * @example
 * // 1. loading private key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN RSA PRIVATE KEY..., "passcode");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN PRIVATE KEY...", "passcode");
 * // 2. loading public key from PEM string
 * keyObj = KEYUTIL.getKey("-----BEGIN PUBLIC KEY...");
 * keyObj = KEYUTIL.getKey("-----BEGIN X509 CERTIFICATE...");
 * // 3. loading hexadecimal PKCS#5/PKCS#8 key
 * keyObj = KEYUTIL.getKey("308205c1...", null, "pkcs8pub");
 * keyObj = KEYUTIL.getKey("3082048b...", null, "pkcs5prv");
 * // 4. loading JSON Web Key(JWK)
 * keyObj = KEYUTIL.getKey({kty: "RSA", n: "0vx7...", e: "AQAB"});
 * keyObj = KEYUTIL.getKey({kty: "EC", crv: "P-256", 
 *                          x: "MKBC...", y: "4Etl6...", d: "870Mb..."});
 * // 5. bare hexadecimal key
 * keyObj = KEYUTIL.getKey({n: "75ab..", e: "010001"});
 */
KEYUTIL.getKey = function(param, passcode, hextype) {
    // 1. by key RSAKey/KJUR.crypto.ECDSA/KJUR.crypto.DSA object
    if (typeof RSAKey != 'undefined' && param instanceof RSAKey)
        return param;
    if (typeof KJUR.crypto.ECDSA != 'undefined' && param instanceof KJUR.crypto.ECDSA)
        return param;
    if (typeof KJUR.crypto.DSA != 'undefined' && param instanceof KJUR.crypto.DSA)
        return param;

    // 2. by parameters of key

    // 2.1. bare ECC
    // 2.1.1. bare ECC public key by hex values
    if (param.curve !== undefined &&
	param.xy !== undefined && param.d === undefined) {
        return new KJUR.crypto.ECDSA({pub: param.xy, curve: param.curve});
    }

    // 2.1.2. bare ECC private key by hex values
    if (param.curve !== undefined && param.d !== undefined) {
        return new KJUR.crypto.ECDSA({prv: param.d, curve: param.curve});
    }

    // 2.2. bare RSA
    // 2.2.1. bare RSA public key by hex values
    if (param.kty === undefined &&
	param.n !== undefined && param.e !== undefined &&
        param.d === undefined) {
        var key = new RSAKey();
        key.setPublic(param.n, param.e);
        return key;
    }

    // 2.2.2. bare RSA private key with P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p !== undefined &&
	param.q !== undefined &&
        param.dp !== undefined &&
	param.dq !== undefined &&
	param.co !== undefined &&
        param.qi === undefined) {
        var key = new RSAKey();
        key.setPrivateEx(param.n, param.e, param.d, param.p, param.q,
                         param.dp, param.dq, param.co);
        return key;
    }

    // 2.2.3. bare RSA public key without P/Q/DP/DQ/COEFF by hex values
    if (param.kty === undefined &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
        param.p === undefined) {
        var key = new RSAKey();
        key.setPrivate(param.n, param.e, param.d);
        return key;
    }

    // 2.3. bare DSA
    // 2.3.1. bare DSA public key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x === undefined) {
        var key = new KJUR.crypto.DSA();
        key.setPublic(param.p, param.q, param.g, param.y);
        return key;
    }

    // 2.3.2. bare DSA private key by hex values
    if (param.p !== undefined && param.q !== undefined &&
	param.g !== undefined &&
        param.y !== undefined && param.x !== undefined) {
        var key = new KJUR.crypto.DSA();
        key.setPrivate(param.p, param.q, param.g, param.y, param.x);
        return key;
    }

    // 3. JWK
    // 3.1. JWK RSA
    // 3.1.1. JWK RSA public key by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d === undefined) {
	var key = new RSAKey();
	key.setPublic(b64utohex(param.n), b64utohex(param.e));
	return key;
    }

    // 3.1.2. JWK RSA private key with p/q/dp/dq/coeff by b64u values
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined &&
	param.p !== undefined &&
	param.q !== undefined &&
	param.dp !== undefined &&
	param.dq !== undefined &&
	param.qi !== undefined) {
	var key = new RSAKey();
        key.setPrivateEx(b64utohex(param.n),
			 b64utohex(param.e),
			 b64utohex(param.d),
			 b64utohex(param.p),
			 b64utohex(param.q),
                         b64utohex(param.dp),
			 b64utohex(param.dq),
			 b64utohex(param.qi));
	return key;
    }

    // 3.1.3. JWK RSA private key without p/q/dp/dq/coeff by b64u
    //        since jsrsasign 5.0.0 keyutil 1.0.11
    if (param.kty === "RSA" &&
	param.n !== undefined &&
	param.e !== undefined &&
	param.d !== undefined) {
	var key = new RSAKey();
        key.setPrivate(b64utohex(param.n),
		       b64utohex(param.e),
		       b64utohex(param.d));
	return key;
    }

    // 3.2. JWK ECC
    // 3.2.1. JWK ECC public key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d === undefined) {
	var ec = new KJUR.crypto.ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keylen / 4;
        var hX   = ("0000000000" + b64utohex(param.x)).slice(- charlen);
        var hY   = ("0000000000" + b64utohex(param.y)).slice(- charlen);
        var hPub = "04" + hX + hY;
	ec.setPublicKeyHex(hPub);
	return ec;
    }

    // 3.2.2. JWK ECC private key by b64u values
    if (param.kty === "EC" &&
	param.crv !== undefined &&
	param.x !== undefined &&
	param.y !== undefined &&
        param.d !== undefined) {
	var ec = new KJUR.crypto.ECDSA({"curve": param.crv});
	var charlen = ec.ecparams.keylen / 4;
        var hPrv = ("0000000000" + b64utohex(param.d)).slice(- charlen);
	ec.setPrivateKeyHex(hPrv);
	return ec;
    }
    
    // 4. by PEM certificate (-----BEGIN ... CERTIFITE----)
    if (param.indexOf("-END CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END X509 CERTIFICATE-", 0) != -1 ||
        param.indexOf("-END TRUSTED CERTIFICATE-", 0) != -1) {
        return X509.getPublicKeyFromCertPEM(param);
    }

    // 4. public key by PKCS#8 hexadecimal string
    if (hextype === "pkcs8pub") {
        return KEYUTIL.getKeyFromPublicPKCS8Hex(param);
    }

    // 5. public key by PKCS#8 PEM string
    if (param.indexOf("-END PUBLIC KEY-") != -1) {
        return KEYUTIL.getKeyFromPublicPKCS8PEM(param);
    }
    
    // 6. private key by PKCS#5 plain hexadecimal RSA string
    if (hextype === "pkcs5prv") {
        var key = new RSAKey();
        key.readPrivateKeyFromASN1HexString(param);
        return key;
    }

    // 7. private key by plain PKCS#5 hexadecimal RSA string
    if (hextype === "pkcs5prv") {
        var key = new RSAKey();
        key.readPrivateKeyFromASN1HexString(param);
        return key;
    }

    // 8. private key by plain PKCS#5 PEM RSA string 
    //    getKey("-----BEGIN RSA PRIVATE KEY-...")
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {
        var hex = KEYUTIL.getHexFromPEM(param, "RSA PRIVATE KEY");
        return KEYUTIL.getKey(hex, null, "pkcs5prv");
    }

    // 8.2. private key by plain PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") == -1) {

        var hKey = this.getHexFromPEM(param, "DSA PRIVATE KEY");
        var p = ASN1HEX.getVbyList(hKey, 0, [1], "02");
        var q = ASN1HEX.getVbyList(hKey, 0, [2], "02");
        var g = ASN1HEX.getVbyList(hKey, 0, [3], "02");
        var y = ASN1HEX.getVbyList(hKey, 0, [4], "02");
        var x = ASN1HEX.getVbyList(hKey, 0, [5], "02");
        var key = new KJUR.crypto.DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 9. private key by plain PKCS#8 PEM ECC/RSA string
    if (param.indexOf("-END PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(param);
    }

    // 10. private key by encrypted PKCS#5 PEM RSA string
    if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        return KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM(param, passcode);
    }

    // 10.2. private key by encrypted PKCS#5 PEM ECDSA string
    if (param.indexOf("-END EC PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = KEYUTIL.getDecryptedKeyHex(param, passcode);

        var key = ASN1HEX.getVbyList(hKey, 0, [1], "04");
        var curveNameOidHex = ASN1HEX.getVbyList(hKey, 0, [2,0], "06");
        var pubkey = ASN1HEX.getVbyList(hKey, 0, [3,0], "03").substr(2);
        var curveName = "";

        if (KJUR.crypto.OID.oidhex2name[curveNameOidHex] !== undefined) {
            curveName = KJUR.crypto.OID.oidhex2name[curveNameOidHex];
        } else {
            throw "undefined OID(hex) in KJUR.crypto.OID: " + curveNameOidHex;
        }

        var ec = new KJUR.crypto.ECDSA({'name': curveName});
        ec.setPublicKeyHex(pubkey);
        ec.setPrivateKeyHex(key);
        ec.isPublic = false;
        return ec;
    }

    // 10.3. private key by encrypted PKCS#5 PEM DSA string
    if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
        param.indexOf("4,ENCRYPTED") != -1) {
        var hKey = KEYUTIL.getDecryptedKeyHex(param, passcode);
        var p = ASN1HEX.getVbyList(hKey, 0, [1], "02");
        var q = ASN1HEX.getVbyList(hKey, 0, [2], "02");
        var g = ASN1HEX.getVbyList(hKey, 0, [3], "02");
        var y = ASN1HEX.getVbyList(hKey, 0, [4], "02");
        var x = ASN1HEX.getVbyList(hKey, 0, [5], "02");
        var key = new KJUR.crypto.DSA();
        key.setPrivate(new BigInteger(p, 16),
                       new BigInteger(q, 16),
                       new BigInteger(g, 16),
                       new BigInteger(y, 16),
                       new BigInteger(x, 16));
        return key;
    }

    // 11. private key by encrypted PKCS#8 hexadecimal RSA/ECDSA string
    if (param.indexOf("-END ENCRYPTED PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromEncryptedPKCS8PEM(param, passcode);
    }

    throw "not supported argument";
};

/**
 * @name generateKeypair
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {String} alg 'RSA' or 'EC'
 * @param {Object} keylenOrCurve key length for RSA or curve name for EC
 * @return {Array} associative array of keypair which has prvKeyObj and pubKeyObj parameters
 * @since keyutil 1.0.1
 * @description
 * This method generates a key pair of public key algorithm.
 * The result will be an associative array which has following
 * parameters:
 * <ul>
 * <li>prvKeyObj - RSAKey or ECDSA object of private key</li>
 * <li>pubKeyObj - RSAKey or ECDSA object of public key</li>
 * </ul>
 * NOTE1: As for RSA algoirthm, public exponent has fixed
 * value '0x10001'.
 * NOTE2: As for EC algorithm, supported names of curve are
 * secp256r1, secp256k1 and secp384r1.
 * NOTE3: DSA is not supported yet.
 * @example
 * var rsaKeypair = KEYUTIL.generateKeypair("RSA", 1024);
 * var ecKeypair = KEYUTIL.generateKeypair("EC", "secp256r1");
 *
 */
KEYUTIL.generateKeypair = function(alg, keylenOrCurve) {
    if (alg == "RSA") {
        var keylen = keylenOrCurve;
        var prvKey = new RSAKey();
        prvKey.generate(keylen, '10001');
        prvKey.isPrivate = true;
        prvKey.isPublic = true;
        
        var pubKey = new RSAKey();
        var hN = prvKey.n.toString(16);
        var hE = prvKey.e.toString(16);
        pubKey.setPublic(hN, hE);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;
        
        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else if (alg == "EC") {
        var curve = keylenOrCurve;
        var ec = new KJUR.crypto.ECDSA({curve: curve});
        var keypairHex = ec.generateKeyPairHex();

        var prvKey = new KJUR.crypto.ECDSA({curve: curve});
        prvKey.setPrivateKeyHex(keypairHex.ecprvhex);
        prvKey.isPrivate = true;
        prvKey.isPublic = false;

        var pubKey = new KJUR.crypto.ECDSA({curve: curve});
        pubKey.setPublicKeyHex(keypairHex.ecpubhex);
        pubKey.isPrivate = false;
        pubKey.isPublic = true;

        var result = {};
        result.prvKeyObj = prvKey;
        result.pubKeyObj = pubKey;
        return result;
    } else {
        throw "unknown algorithm: " + alg;
    }
};

/**
 * get PEM formatted private or public key file from a RSA/ECDSA/DSA key object
 * @name getPEM
 * @memberOf KEYUTIL
 * @function
 * @static
 * @param {Object} keyObjOrHex key object {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} to encode to
 * @param {String} formatType (OPTION) output format type of "PKCS1PRV", "PKCS5PRV" or "PKCS8PRV" for private key
 * @param {String} passwd (OPTION) password to protect private key
 * @param {String} encAlg (OPTION) encryption algorithm for PKCS#5. currently supports DES-CBC, DES-EDE3-CBC and AES-{128,192,256}-CBC
 * @since keyutil 1.0.4
 * @description
 * <dl>
 * <dt><b>NOTE1:</b>
 * <dd>
 * PKCS#5 encrypted private key protection algorithm supports DES-CBC, 
 * DES-EDE3-CBC and AES-{128,192,256}-CBC
 * <dt><b>NOTE2:</b>
 * <dd>
 * OpenSSL supports
 * </dl>
 * @example
 * KEUUTIL.getPEM(publicKey) =&gt; generates PEM PKCS#8 public key 
 * KEUUTIL.getPEM(privateKey, "PKCS1PRV") =&gt; generates PEM PKCS#1 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass") =&gt; generates PEM PKCS#5 encrypted private key 
 *                                                          with DES-EDE3-CBC (DEFAULT)
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass", "DES-CBC") =&gt; generates PEM PKCS#5 encrypted 
 *                                                                 private key with DES-CBC
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV") =&gt; generates PEM PKCS#8 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV", "pass") =&gt; generates PEM PKCS#8 encrypted private key
 *                                                      with PBKDF2_HmacSHA1_3DES
 */
KEYUTIL.getPEM = function(keyObjOrHex, formatType, passwd, encAlg, hexType) {
    var ns1 = KJUR.asn1;
    var ns2 = KJUR.crypto;

    function _rsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.n}},
                {"int": keyObjOrHex.e},
                {"int": {"bigint": keyObjOrHex.d}},
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.dmp1}},
                {"int": {"bigint": keyObjOrHex.dmq1}},
                {"int": {"bigint": keyObjOrHex.coeff}}
            ]
        });
        return asn1Obj;
    };

    function _ecdsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj2 = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 1 },
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}},
                {"tag": ['a0', true, {'oid': {'name': keyObjOrHex.curveName}}]},
                {"tag": ['a1', true, {'bitstr': {'hex': '00' + keyObjOrHex.pubKeyHex}}]}
            ]
        });
        return asn1Obj2;
    };

    function _dsaprv2asn1obj(keyObjOrHex) {
        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0 },
                {"int": {"bigint": keyObjOrHex.p}},
                {"int": {"bigint": keyObjOrHex.q}},
                {"int": {"bigint": keyObjOrHex.g}},
                {"int": {"bigint": keyObjOrHex.y}},
                {"int": {"bigint": keyObjOrHex.x}}
            ]
        });
        return asn1Obj;
    };

    // 1. public key

    // x. PEM PKCS#8 public key of RSA/ECDSA/DSA public key object
    if (((typeof RSAKey != "undefined" && keyObjOrHex instanceof RSAKey) ||
         (typeof ns2.DSA != "undefined" && keyObjOrHex instanceof ns2.DSA) ||
         (typeof ns2.ECDSA != "undefined" && keyObjOrHex instanceof ns2.ECDSA)) &&
        keyObjOrHex.isPublic == true &&
        (formatType === undefined || formatType == "PKCS8PUB")) {
        var asn1Obj = new KJUR.asn1.x509.SubjectPublicKeyInfo(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PUBLIC KEY");
    }
    
    // 2. private

    // x. PEM PKCS#1 plain private key of RSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "RSA PRIVATE KEY");
    }

    // x. PEM PKCS#1 plain private key of ECDSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj1 = new KJUR.asn1.DERObjectIdentifier({'name': keyObjOrHex.curveName});
        var asn1Hex1 = asn1Obj1.getEncodedHex();
        var asn1Obj2 = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex2 = asn1Obj2.getEncodedHex();

        var s = "";
        s += ns1.ASN1Util.getPEMStringFromHex(asn1Hex1, "EC PARAMETERS");
        s += ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "EC PRIVATE KEY");
        return s;
    }

    // x. PEM PKCS#1 plain private key of DSA private key object
    if (formatType == "PKCS1PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        (passwd === undefined || passwd == null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();
        return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "DSA PRIVATE KEY");
    }

    // 3. private

    // x. PEM PKCS#5 encrypted private key of RSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _rsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", asn1Hex, passwd, encAlg);
    }

    // x. PEM PKCS#5 encrypted private key of ECDSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof KJUR.crypto.ECDSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _ecdsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("EC", asn1Hex, passwd, encAlg);
    }

    // x. PEM PKCS#5 encrypted private key of DSA private key object
    if (formatType == "PKCS5PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        (passwd !== undefined && passwd != null) &&
        keyObjOrHex.isPrivate  == true) {

        var asn1Obj = _dsaprv2asn1obj(keyObjOrHex);
        var asn1Hex = asn1Obj.getEncodedHex();

        if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA", asn1Hex, passwd, encAlg);
    }

    // x. ======================================================================

    var _getEncryptedPKCS8 = function(plainKeyHex, passcode) {
        var info = _getEencryptedPKCS8Info(plainKeyHex, passcode);
        //alert("iv=" + info.encryptionSchemeIV);
        //alert("info.ciphertext2[" + info.ciphertext.length + "=" + info.ciphertext);
        var asn1Obj = new KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"seq": [
                    {"oid": {"name": "pkcs5PBES2"}},
                    {"seq": [
                        {"seq": [
                            {"oid": {"name": "pkcs5PBKDF2"}},
                            {"seq": [
                                {"octstr": {"hex": info.pbkdf2Salt}},
                                {"int": info.pbkdf2Iter}
                            ]}
                        ]},
                        {"seq": [
                            {"oid": {"name": "des-EDE3-CBC"}},
                            {"octstr": {"hex": info.encryptionSchemeIV}}
                        ]}
                    ]}
                ]},
                {"octstr": {"hex": info.ciphertext}}
            ]
        });
        return asn1Obj.getEncodedHex();
    };

    var _getEencryptedPKCS8Info = function(plainKeyHex, passcode) {
        var pbkdf2Iter = 100;
        var pbkdf2SaltWS = CryptoJS.lib.WordArray.random(8);
        var encryptionSchemeAlg = "DES-EDE3-CBC";
        var encryptionSchemeIVWS = CryptoJS.lib.WordArray.random(8);
        // PBKDF2 key
        var pbkdf2KeyWS = CryptoJS.PBKDF2(passcode, 
                                          pbkdf2SaltWS, { "keySize": 192/32,
                                                          "iterations": pbkdf2Iter });
        // ENCRYPT
        var plainKeyWS = CryptoJS.enc.Hex.parse(plainKeyHex);
        var encryptedKeyHex = 
            CryptoJS.TripleDES.encrypt(plainKeyWS, pbkdf2KeyWS, { "iv": encryptionSchemeIVWS }) + "";

        //alert("encryptedKeyHex=" + encryptedKeyHex);

        var info = {};
        info.ciphertext = encryptedKeyHex;
        //alert("info.ciphertext=" + info.ciphertext);
        info.pbkdf2Salt = CryptoJS.enc.Hex.stringify(pbkdf2SaltWS);
        info.pbkdf2Iter = pbkdf2Iter;
        info.encryptionSchemeAlg = encryptionSchemeAlg;
        info.encryptionSchemeIV = CryptoJS.enc.Hex.stringify(encryptionSchemeIVWS);
        return info;
    };

    // x. PEM PKCS#8 plain private key of RSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof RSAKey != "undefined" &&
        keyObjOrHex instanceof RSAKey &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = _rsaprv2asn1obj(keyObjOrHex);
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [{"oid": {"name": "rsaEncryption"}},{"null": true}]},
                {"octstr": {"hex": keyHex}}
            ]
        });
        var asn1Hex = asn1Obj.getEncodedHex();

        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    // x. PEM PKCS#8 plain private key of ECDSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof KJUR.crypto.ECDSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.ECDSA &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = new KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 1},
                {"octstr": {"hex": keyObjOrHex.prvKeyHex}},
                {"tag": ['a1', true, {"bitstr": {"hex": "00" + keyObjOrHex.pubKeyHex}}]}
            ]
        });
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "ecPublicKey"}},
                    {"oid": {"name": keyObjOrHex.curveName}}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.getEncodedHex();
        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    // x. PEM PKCS#8 plain private key of DSA private key object
    if (formatType == "PKCS8PRV" &&
        typeof KJUR.crypto.DSA != "undefined" &&
        keyObjOrHex instanceof KJUR.crypto.DSA &&
        keyObjOrHex.isPrivate  == true) {

        var keyObj = new KJUR.asn1.DERInteger({'bigint': keyObjOrHex.x});
        var keyHex = keyObj.getEncodedHex();

        var asn1Obj = KJUR.asn1.ASN1Util.newObject({
            "seq": [
                {"int": 0},
                {"seq": [
                    {"oid": {"name": "dsa"}},
                    {"seq": [
                        {"int": {"bigint": keyObjOrHex.p}},
                        {"int": {"bigint": keyObjOrHex.q}},
                        {"int": {"bigint": keyObjOrHex.g}}
                    ]}
                ]},
                {"octstr": {"hex": keyHex}}
            ]
        });

        var asn1Hex = asn1Obj.getEncodedHex();
        if (passwd === undefined || passwd == null) {
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex, "PRIVATE KEY");
        } else {
            var asn1Hex2 = _getEncryptedPKCS8(asn1Hex, passwd);
            return ns1.ASN1Util.getPEMStringFromHex(asn1Hex2, "ENCRYPTED PRIVATE KEY");
        }
    }

    throw "unsupported object nor format";
};

// -- PUBLIC METHODS FOR CSR -------------------------------------------------------

/**
 * get RSAKey/DSA/ECDSA public key object from PEM formatted PKCS#10 CSR string
 * @name getKeyFromCSRPEM
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrPEM PEM formatted PKCS#10 CSR string
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRPEM = function(csrPEM) {
    var csrHex = KEYUTIL.getHexFromPEM(csrPEM, "CERTIFICATE REQUEST");
    var key = KEYUTIL.getKeyFromCSRHex(csrHex);
    return key;
};

/**
 * get RSAKey/DSA/ECDSA public key object from hexadecimal string of PKCS#10 CSR
 * @name getKeyFromCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Object} RSAKey/DSA/ECDSA public key object
 * @since keyutil 1.0.5
 */
KEYUTIL.getKeyFromCSRHex = function(csrHex) {
    var info = KEYUTIL.parseCSRHex(csrHex);
    var key = KEYUTIL.getKey(info.p8pubkeyhex, null, "pkcs8pub");
    return key;
};

/**
 * parse hexadecimal string of PKCS#10 CSR (certificate signing request)
 * @name parseCSRHex
 * @memberOf KEYUTIL
 * @function
 * @param {String} csrHex hexadecimal string of PKCS#10 CSR
 * @return {Array} associative array of parsed CSR
 * @since keyutil 1.0.5
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>p8pubkeyhex - hexadecimal string of subject public key in PKCS#8</li>
 * </ul>
 */
KEYUTIL.parseCSRHex = function(csrHex) {
    var result = {};
    var h = csrHex;

    // 1. sequence
    if (h.substr(0, 2) != "30")
        throw "malformed CSR(code:001)"; // not sequence

    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0);
    if (a1.length < 1)
        throw "malformed CSR(code:002)"; // short length

    // 2. 2nd sequence
    if (h.substr(a1[0], 2) != "30")
        throw "malformed CSR(code:003)"; // not sequence

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(h, a1[0]);
    if (a2.length < 3)
        throw "malformed CSR(code:004)"; // 2nd seq short elem

    result.p8pubkeyhex = ASN1HEX.getHexOfTLV_AtObj(h, a2[2]);

    return result;
};
/*! asn1-1.0.9.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1.js - ASN.1 DER encoder classes
 *
 * Copyright (c) 2013-2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version asn1 1.0.9 (2015-Nov-26)
 * @since jsrsasign 2.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * <p>
 * This name space provides following name spaces:
 * <ul>
 * <li>{@link KJUR.asn1} - ASN.1 primitive hexadecimal encoder</li>
 * <li>{@link KJUR.asn1.x509} - ASN.1 structure for X.509 certificate and CRL</li>
 * <li>{@link KJUR.crypto} - Java Cryptographic Extension(JCE) style MessageDigest/Signature 
 * class and utilities</li>
 * </ul>
 * </p> 
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's ASN.1 class library name space
 * <p>
 * This is ITU-T X.690 ASN.1 DER encoder class library and
 * class structure and methods is very similar to 
 * org.bouncycastle.asn1 package of 
 * well known BouncyCaslte Cryptography Library.
 * <h4>PROVIDING ASN.1 PRIMITIVES</h4>
 * Here are ASN.1 DER primitive classes.
 * <ul>
 * <li>0x01 {@link KJUR.asn1.DERBoolean}</li>
 * <li>0x02 {@link KJUR.asn1.DERInteger}</li>
 * <li>0x03 {@link KJUR.asn1.DERBitString}</li>
 * <li>0x04 {@link KJUR.asn1.DEROctetString}</li>
 * <li>0x05 {@link KJUR.asn1.DERNull}</li>
 * <li>0x06 {@link KJUR.asn1.DERObjectIdentifier}</li>
 * <li>0x0a {@link KJUR.asn1.DEREnumerated}</li>
 * <li>0x0c {@link KJUR.asn1.DERUTF8String}</li>
 * <li>0x12 {@link KJUR.asn1.DERNumericString}</li>
 * <li>0x13 {@link KJUR.asn1.DERPrintableString}</li>
 * <li>0x14 {@link KJUR.asn1.DERTeletexString}</li>
 * <li>0x16 {@link KJUR.asn1.DERIA5String}</li>
 * <li>0x17 {@link KJUR.asn1.DERUTCTime}</li>
 * <li>0x18 {@link KJUR.asn1.DERGeneralizedTime}</li>
 * <li>0x30 {@link KJUR.asn1.DERSequence}</li>
 * <li>0x31 {@link KJUR.asn1.DERSet}</li>
 * </ul>
 * <h4>OTHER ASN.1 CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.ASN1Object}</li>
 * <li>{@link KJUR.asn1.DERAbstractString}</li>
 * <li>{@link KJUR.asn1.DERAbstractTime}</li>
 * <li>{@link KJUR.asn1.DERAbstractStructured}</li>
 * <li>{@link KJUR.asn1.DERTaggedObject}</li>
 * </ul>
 * <h4>SUB NAME SPACES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.cades} - CAdES long term signature format</li>
 * <li>{@link KJUR.asn1.cms} - Cryptographic Message Syntax</li>
 * <li>{@link KJUR.asn1.csr} - Certificate Signing Request (CSR/PKCS#10)</li>
 * <li>{@link KJUR.asn1.tsp} - RFC 3161 Timestamping Protocol Format</li>
 * <li>{@link KJUR.asn1.x509} - RFC 5280 X.509 certificate and CRL</li>
 * </ul>
 * </p>
 * NOTE: Please ignore method summary and document of this namespace. 
 * This caused by a bug of jsdoc2.
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * ASN1 utilities class
 * @name KJUR.asn1.ASN1Util
 * @class ASN1 utilities class
 * @since asn1 1.0.2
 */
KJUR.asn1.ASN1Util = new function() {
    this.integerToByteHex = function(i) {
        var h = i.toString(16);
        if ((h.length % 2) == 1) h = '0' + h;
        return h;
    };
    this.bigIntToMinTwosComplementsHex = function(bigIntegerValue) {
        var h = bigIntegerValue.toString(16);
        if (h.substr(0, 1) != '-') {
            if (h.length % 2 == 1) {
                h = '0' + h;
            } else {
                if (! h.match(/^[0-7]/)) {
                    h = '00' + h;
                }
            }
        } else {
            var hPos = h.substr(1);
            var xorLen = hPos.length;
            if (xorLen % 2 == 1) {
                xorLen += 1;
            } else {
                if (! h.match(/^[0-7]/)) {
                    xorLen += 2;
                }
            }
            var hMask = '';
            for (var i = 0; i < xorLen; i++) {
                hMask += 'f';
            }
            var biMask = new BigInteger(hMask, 16);
            var biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE);
            h = biNeg.toString(16).replace(/^-/, '');
        }
        return h;
    };
    /**
     * get PEM string from hexadecimal data and header string
     * @name getPEMStringFromHex
     * @memberOf KJUR.asn1.ASN1Util
     * @function
     * @param {String} dataHex hexadecimal string of PEM body
     * @param {String} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
     * @return {String} PEM formatted string of input data
     * @description
     * @example
     * var pem  = KJUR.asn1.ASN1Util.getPEMStringFromHex('616161', 'RSA PRIVATE KEY');
     * // value of pem will be:
     * -----BEGIN PRIVATE KEY-----
     * YWFh
     * -----END PRIVATE KEY-----
     */
    this.getPEMStringFromHex = function(dataHex, pemHeader) {
        //var dataB64 = hextob64(dataHex);
        var ns1 = KJUR.asn1;
        var dataWA = CryptoJS.enc.Hex.parse(dataHex);
        var dataB64 = CryptoJS.enc.Base64.stringify(dataWA);
        var pemBody = dataB64.replace(/(.{64})/g, "$1\r\n");
        pemBody = pemBody.replace(/\r\n$/, '');
        return "-----BEGIN " + pemHeader + "-----\r\n" + 
            pemBody + 
            "\r\n-----END " + pemHeader + "-----\r\n";
    };

    /**
     * generate ASN1Object specifed by JSON parameters
     * @name newObject
     * @memberOf KJUR.asn1.ASN1Util
     * @function
     * @param {Array} param JSON parameter to generate ASN1Object
     * @return {KJUR.asn1.ASN1Object} generated object
     * @since asn1 1.0.3
     * @description
     * generate any ASN1Object specified by JSON param
     * including ASN.1 primitive or structured.
     * Generally 'param' can be described as follows:
     * <blockquote>
     * {TYPE-OF-ASNOBJ: ASN1OBJ-PARAMETER}
     * </blockquote>
     * 'TYPE-OF-ASN1OBJ' can be one of following symbols:
     * <ul>
     * <li>'bool' - DERBoolean</li>
     * <li>'int' - DERInteger</li>
     * <li>'bitstr' - DERBitString</li>
     * <li>'octstr' - DEROctetString</li>
     * <li>'null' - DERNull</li>
     * <li>'oid' - DERObjectIdentifier</li>
     * <li>'enum' - DEREnumerated</li>
     * <li>'utf8str' - DERUTF8String</li>
     * <li>'numstr' - DERNumericString</li>
     * <li>'prnstr' - DERPrintableString</li>
     * <li>'telstr' - DERTeletexString</li>
     * <li>'ia5str' - DERIA5String</li>
     * <li>'utctime' - DERUTCTime</li>
     * <li>'gentime' - DERGeneralizedTime</li>
     * <li>'seq' - DERSequence</li>
     * <li>'set' - DERSet</li>
     * <li>'tag' - DERTaggedObject</li>
     * </ul>
     * @example
     * newObject({'prnstr': 'aaa'});
     * newObject({'seq': [{'int': 3}, {'prnstr': 'aaa'}]})
     * // ASN.1 Tagged Object
     * newObject({'tag': {'tag': 'a1', 
     *                    'explicit': true,
     *                    'obj': {'seq': [{'int': 3}, {'prnstr': 'aaa'}]}}});
     * // more simple representation of ASN.1 Tagged Object
     * newObject({'tag': ['a1',
     *                    true,
     *                    {'seq': [
     *                      {'int': 3}, 
     *                      {'prnstr': 'aaa'}]}
     *                   ]});
     */
    this.newObject = function(param) {
        var ns1 = KJUR.asn1;
        var keys = Object.keys(param);
        if (keys.length != 1)
            throw "key of param shall be only one.";
        var key = keys[0];

        if (":bool:int:bitstr:octstr:null:oid:enum:utf8str:numstr:prnstr:telstr:ia5str:utctime:gentime:seq:set:tag:".indexOf(":" + key + ":") == -1)
            throw "undefined key: " + key;

        if (key == "bool")    return new ns1.DERBoolean(param[key]);
        if (key == "int")     return new ns1.DERInteger(param[key]);
        if (key == "bitstr")  return new ns1.DERBitString(param[key]);
        if (key == "octstr")  return new ns1.DEROctetString(param[key]);
        if (key == "null")    return new ns1.DERNull(param[key]);
        if (key == "oid")     return new ns1.DERObjectIdentifier(param[key]);
        if (key == "enum")    return new ns1.DEREnumerated(param[key]);
        if (key == "utf8str") return new ns1.DERUTF8String(param[key]);
        if (key == "numstr")  return new ns1.DERNumericString(param[key]);
        if (key == "prnstr")  return new ns1.DERPrintableString(param[key]);
        if (key == "telstr")  return new ns1.DERTeletexString(param[key]);
        if (key == "ia5str")  return new ns1.DERIA5String(param[key]);
        if (key == "utctime") return new ns1.DERUTCTime(param[key]);
        if (key == "gentime") return new ns1.DERGeneralizedTime(param[key]);

        if (key == "seq") {
            var paramList = param[key];
            var a = [];
            for (var i = 0; i < paramList.length; i++) {
                var asn1Obj = ns1.ASN1Util.newObject(paramList[i]);
                a.push(asn1Obj);
            }
            return new ns1.DERSequence({'array': a});
        }

        if (key == "set") {
            var paramList = param[key];
            var a = [];
            for (var i = 0; i < paramList.length; i++) {
                var asn1Obj = ns1.ASN1Util.newObject(paramList[i]);
                a.push(asn1Obj);
            }
            return new ns1.DERSet({'array': a});
        }

        if (key == "tag") {
            var tagParam = param[key];
            if (Object.prototype.toString.call(tagParam) === '[object Array]' &&
                tagParam.length == 3) {
                var obj = ns1.ASN1Util.newObject(tagParam[2]);
                return new ns1.DERTaggedObject({tag: tagParam[0], explicit: tagParam[1], obj: obj});
            } else {
                var newParam = {};
                if (tagParam.explicit !== undefined)
                    newParam.explicit = tagParam.explicit;
                if (tagParam.tag !== undefined)
                    newParam.tag = tagParam.tag;
                if (tagParam.obj === undefined)
                    throw "obj shall be specified for 'tag'.";
                newParam.obj = ns1.ASN1Util.newObject(tagParam.obj);
                return new ns1.DERTaggedObject(newParam);
            }
        }
    };

    /**
     * get encoded hexadecimal string of ASN1Object specifed by JSON parameters
     * @name jsonToASN1HEX
     * @memberOf KJUR.asn1.ASN1Util
     * @function
     * @param {Array} param JSON parameter to generate ASN1Object
     * @return hexadecimal string of ASN1Object
     * @since asn1 1.0.4
     * @description
     * As for ASN.1 object representation of JSON object,
     * please see {@link newObject}.
     * @example
     * jsonToASN1HEX({'prnstr': 'aaa'}); 
     */
    this.jsonToASN1HEX = function(param) {
        var asn1Obj = this.newObject(param);
        return asn1Obj.getEncodedHex();
    };
};

/**
 * get dot noted oid number string from hexadecimal value of OID
 * @name oidHexToInt
 * @memberOf KJUR.asn1.ASN1Util
 * @function
 * @param {String} hex hexadecimal value of object identifier
 * @return {String} dot noted string of object identifier
 * @since jsrsasign 4.8.3 asn1 1.0.7
 * @description
 * This static method converts from hexadecimal string representation of 
 * ASN.1 value of object identifier to oid number string.
 * @example
 * KJUR.asn1.ASN1Util.oidHexToInt('550406') &rarr; "2.5.4.6"
 */
KJUR.asn1.ASN1Util.oidHexToInt = function(hex) {
    var s = "";
    var i01 = parseInt(hex.substr(0, 2), 16);
    var i0 = Math.floor(i01 / 40);
    var i1 = i01 % 40;
    var s = i0 + "." + i1;

    var binbuf = "";
    for (var i = 2; i < hex.length; i += 2) {
	var value = parseInt(hex.substr(i, 2), 16);
        var bin = ("00000000" + value.toString(2)).slice(- 8);
	binbuf = binbuf + bin.substr(1, 7);
	if (bin.substr(0, 1) == "0") {
	    var bi = new BigInteger(binbuf, 2);
	    s = s + "." + bi.toString(10);
	    binbuf = "";
	}
    };

    return s;
};

/**
 * get hexadecimal value of object identifier from dot noted oid value
 * @name oidIntToHex
 * @memberOf KJUR.asn1.ASN1Util
 * @function
 * @param {String} oidString dot noted string of object identifier
 * @return {String} hexadecimal value of object identifier
 * @since jsrsasign 4.8.3 asn1 1.0.7
 * @description
 * This static method converts from object identifier value string.
 * to hexadecimal string representation of it.
 * @example
 * KJUR.asn1.ASN1Util.oidIntToHex("2.5.4.6") &rarr; "550406"
 */
KJUR.asn1.ASN1Util.oidIntToHex = function(oidString) {
    var itox = function(i) {
        var h = i.toString(16);
        if (h.length == 1) h = '0' + h;
        return h;
    };

    var roidtox = function(roid) {
        var h = '';
        var bi = new BigInteger(roid, 10);
        var b = bi.toString(2);
        var padLen = 7 - b.length % 7;
        if (padLen == 7) padLen = 0;
        var bPad = '';
        for (var i = 0; i < padLen; i++) bPad += '0';
        b = bPad + b;
        for (var i = 0; i < b.length - 1; i += 7) {
            var b8 = b.substr(i, 7);
            if (i != b.length - 7) b8 = '1' + b8;
            h += itox(parseInt(b8, 2));
        }
        return h;
    };
    
    if (! oidString.match(/^[0-9.]+$/)) {
        throw "malformed oid string: " + oidString;
    }
    var h = '';
    var a = oidString.split('.');
    var i0 = parseInt(a[0]) * 40 + parseInt(a[1]);
    h += itox(i0);
    a.splice(0, 2);
    for (var i = 0; i < a.length; i++) {
        h += roidtox(a[i]);
    }
    return h;
};


// ********************************************************************
//  Abstract ASN.1 Classes
// ********************************************************************

// ********************************************************************

/**
 * base class for ASN.1 DER encoder object
 * @name KJUR.asn1.ASN1Object
 * @class base class for ASN.1 DER encoder object
 * @property {Boolean} isModified flag whether internal data was changed
 * @property {String} hTLV hexadecimal string of ASN.1 TLV
 * @property {String} hT hexadecimal string of ASN.1 TLV tag(T)
 * @property {String} hL hexadecimal string of ASN.1 TLV length(L)
 * @property {String} hV hexadecimal string of ASN.1 TLV value(V)
 * @description
 */
KJUR.asn1.ASN1Object = function() {
    var isModified = true;
    var hTLV = null;
    var hT = '00';
    var hL = '00';
    var hV = '';

    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     * @name getLengthHexFromValue
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV length(L)
     */
    this.getLengthHexFromValue = function() {
        if (typeof this.hV == "undefined" || this.hV == null) {
            throw "this.hV is null or undefined.";
        }
        if (this.hV.length % 2 == 1) {
            throw "value hex must be even length: n=" + hV.length + ",v=" + this.hV;
        }
        var n = this.hV.length / 2;
        var hN = n.toString(16);
        if (hN.length % 2 == 1) {
            hN = "0" + hN;
        }
        if (n < 128) {
            return hN;
        } else {
            var hNlen = hN.length / 2;
            if (hNlen > 15) {
                throw "ASN.1 length too long to represent by 8x: n = " + n.toString(16);
            }
            var head = 128 + hNlen;
            return head.toString(16) + hN;
        }
    };

    /**
     * get hexadecimal string of ASN.1 TLV bytes
     * @name getEncodedHex
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV
     */
    this.getEncodedHex = function() {
        if (this.hTLV == null || this.isModified) {
            this.hV = this.getFreshValueHex();
            this.hL = this.getLengthHexFromValue();
            this.hTLV = this.hT + this.hL + this.hV;
            this.isModified = false;
            //alert("first time: " + this.hTLV);
        }
        return this.hTLV;
    };

    /**
     * get hexadecimal string of ASN.1 TLV value(V) bytes
     * @name getValueHex
     * @memberOf KJUR.asn1.ASN1Object
     * @function
     * @return {String} hexadecimal string of ASN.1 TLV value(V) bytes
     */
    this.getValueHex = function() {
        this.getEncodedHex();
        return this.hV;
    }

    this.getFreshValueHex = function() {
        return '';
    };
};

// == BEGIN DERAbstractString ================================================
/**
 * base class for ASN.1 DER string classes
 * @name KJUR.asn1.DERAbstractString
 * @class base class for ASN.1 DER string classes
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @property {String} s internal string of value
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERAbstractString = function(params) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var s = null;
    var hV = null;

    /**
     * get string value of this string object
     * @name getString
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @return {String} string value of this string object
     */
    this.getString = function() {
        return this.s;
    };

    /**
     * set value by a string
     * @name setString
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @param {String} newS value by a string to set
     */
    this.setString = function(newS) {
        this.hTLV = null;
        this.isModified = true;
        this.s = newS;
        this.hV = stohex(this.s);
    };

    /**
     * set value by a hexadecimal string
     * @name setStringHex
     * @memberOf KJUR.asn1.DERAbstractString
     * @function
     * @param {String} newHexString value by a hexadecimal string to set
     */
    this.setStringHex = function(newHexString) {
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = newHexString;
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params == "string") {
            this.setString(params);
        } else if (typeof params['str'] != "undefined") {
            this.setString(params['str']);
        } else if (typeof params['hex'] != "undefined") {
            this.setStringHex(params['hex']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
// == END   DERAbstractString ================================================

// == BEGIN DERAbstractTime ==================================================
/**
 * base class for ASN.1 DER Generalized/UTCTime class
 * @name KJUR.asn1.DERAbstractTime
 * @class base class for ASN.1 DER Generalized/UTCTime class
 * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERAbstractTime = function(params) {
    KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
    var s = null;
    var date = null;

    // --- PRIVATE METHODS --------------------
    this.localDateToUTC = function(d) {
        utc = d.getTime() + (d.getTimezoneOffset() * 60000);
        var utcDate = new Date(utc);
        return utcDate;
    };

    /*
     * format date string by Data object
     * @name formatDate
     * @memberOf KJUR.asn1.AbstractTime;
     * @param {Date} dateObject 
     * @param {string} type 'utc' or 'gen'
     * @param {boolean} withMillis flag for with millisections or not
     * @description
     * 'withMillis' flag is supported from asn1 1.0.6.
     */
    this.formatDate = function(dateObject, type, withMillis) {
        var pad = this.zeroPadding;
        var d = this.localDateToUTC(dateObject);
        var year = String(d.getFullYear());
        if (type == 'utc') year = year.substr(2, 2);
        var month = pad(String(d.getMonth() + 1), 2);
        var day = pad(String(d.getDate()), 2);
        var hour = pad(String(d.getHours()), 2);
        var min = pad(String(d.getMinutes()), 2);
        var sec = pad(String(d.getSeconds()), 2);
        var s = year + month + day + hour + min + sec;
        if (withMillis === true) {
            var millis = d.getMilliseconds();
            if (millis != 0) {
                var sMillis = pad(String(millis), 3);
                sMillis = sMillis.replace(/[0]+$/, "");
                s = s + "." + sMillis;
            }
        }
        return s + "Z";
    };

    this.zeroPadding = function(s, len) {
        if (s.length >= len) return s;
        return new Array(len - s.length + 1).join('0') + s;
    };

    // --- PUBLIC METHODS --------------------
    /**
     * get string value of this string object
     * @name getString
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @return {String} string value of this time object
     */
    this.getString = function() {
        return this.s;
    };

    /**
     * set value by a string
     * @name setString
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @param {String} newS value by a string to set such like "130430235959Z"
     */
    this.setString = function(newS) {
        this.hTLV = null;
        this.isModified = true;
        this.s = newS;
        this.hV = stohex(newS);
    };

    /**
     * set value by a Date object
     * @name setByDateValue
     * @memberOf KJUR.asn1.DERAbstractTime
     * @function
     * @param {Integer} year year of date (ex. 2013)
     * @param {Integer} month month of date between 1 and 12 (ex. 12)
     * @param {Integer} day day of month
     * @param {Integer} hour hours of date
     * @param {Integer} min minutes of date
     * @param {Integer} sec seconds of date
     */
    this.setByDateValue = function(year, month, day, hour, min, sec) {
        var dateObject = new Date(Date.UTC(year, month - 1, day, hour, min, sec, 0));
        this.setByDate(dateObject);
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
// == END   DERAbstractTime ==================================================

// == BEGIN DERAbstractStructured ============================================
/**
 * base class for ASN.1 DER structured class
 * @name KJUR.asn1.DERAbstractStructured
 * @class base class for ASN.1 DER structured class
 * @property {Array} asn1Array internal array of ASN1Object
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERAbstractStructured = function(params) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var asn1Array = null;

    /**
     * set value by array of ASN1Object
     * @name setByASN1ObjectArray
     * @memberOf KJUR.asn1.DERAbstractStructured
     * @function
     * @param {array} asn1ObjectArray array of ASN1Object to set
     */
    this.setByASN1ObjectArray = function(asn1ObjectArray) {
        this.hTLV = null;
        this.isModified = true;
        this.asn1Array = asn1ObjectArray;
    };

    /**
     * append an ASN1Object to internal array
     * @name appendASN1Object
     * @memberOf KJUR.asn1.DERAbstractStructured
     * @function
     * @param {ASN1Object} asn1Object to add
     */
    this.appendASN1Object = function(asn1Object) {
        this.hTLV = null;
        this.isModified = true;
        this.asn1Array.push(asn1Object);
    };

    this.asn1Array = new Array();
    if (typeof params != "undefined") {
        if (typeof params['array'] != "undefined") {
            this.asn1Array = params['array'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);


// ********************************************************************
//  ASN.1 Object Classes
// ********************************************************************

// ********************************************************************
/**
 * class for ASN.1 DER Boolean
 * @name KJUR.asn1.DERBoolean
 * @class class for ASN.1 DER Boolean
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERBoolean = function() {
    KJUR.asn1.DERBoolean.superclass.constructor.call(this);
    this.hT = "01";
    this.hTLV = "0101ff";
};
YAHOO.lang.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER Integer
 * @name KJUR.asn1.DERInteger
 * @class class for ASN.1 DER Integer
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>int - specify initial ASN.1 value(V) by integer value</li>
 * <li>bigint - specify initial ASN.1 value(V) by BigInteger object</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERInteger = function(params) {
    KJUR.asn1.DERInteger.superclass.constructor.call(this);
    this.hT = "02";

    /**
     * set value by Tom Wu's BigInteger object
     * @name setByBigInteger
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {BigInteger} bigIntegerValue to set
     */
    this.setByBigInteger = function(bigIntegerValue) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(bigIntegerValue);
    };

    /**
     * set value by integer value
     * @name setByInteger
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {Integer} integer value to set
     */
    this.setByInteger = function(intValue) {
        var bi = new BigInteger(String(intValue), 10);
        this.setByBigInteger(bi);
    };

    /**
     * set value by integer value
     * @name setValueHex
     * @memberOf KJUR.asn1.DERInteger
     * @function
     * @param {String} hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     * @example
     * new KJUR.asn1.DERInteger(123);
     * new KJUR.asn1.DERInteger({'int': 123});
     * new KJUR.asn1.DERInteger({'hex': '1fad'});
     */
    this.setValueHex = function(newHexString) {
        this.hV = newHexString;
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params['bigint'] != "undefined") {
            this.setByBigInteger(params['bigint']);
        } else if (typeof params['int'] != "undefined") {
            this.setByInteger(params['int']);
        } else if (typeof params == "number") {
            this.setByInteger(params);
        } else if (typeof params['hex'] != "undefined") {
            this.setValueHex(params['hex']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER encoded BitString primitive
 * @name KJUR.asn1.DERBitString
 * @class class for ASN.1 DER encoded BitString primitive
 * @extends KJUR.asn1.ASN1Object
 * @description 
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>bin - specify binary string (ex. '10111')</li>
 * <li>array - specify array of boolean (ex. [true,false,true,true])</li>
 * <li>hex - specify hexadecimal string of ASN.1 value(V) including unused bits</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERBitString = function(params) {
    KJUR.asn1.DERBitString.superclass.constructor.call(this);
    this.hT = "03";

    /**
     * set ASN.1 value(V) by a hexadecimal string including unused bits
     * @name setHexValueIncludingUnusedBits
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {String} newHexStringIncludingUnusedBits
     */
    this.setHexValueIncludingUnusedBits = function(newHexStringIncludingUnusedBits) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = newHexStringIncludingUnusedBits;
    };

    /**
     * set ASN.1 value(V) by unused bit and hexadecimal string of value
     * @name setUnusedBitsAndHexValue
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {Integer} unusedBits
     * @param {String} hValue
     */
    this.setUnusedBitsAndHexValue = function(unusedBits, hValue) {
        if (unusedBits < 0 || 7 < unusedBits) {
            throw "unused bits shall be from 0 to 7: u = " + unusedBits;
        }
        var hUnusedBits = "0" + unusedBits;
        this.hTLV = null;
        this.isModified = true;
        this.hV = hUnusedBits + hValue;
    };

    /**
     * set ASN.1 DER BitString by binary string
     * @name setByBinaryString
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {String} binaryString binary value string (i.e. '10111')
     * @description
     * Its unused bits will be calculated automatically by length of 
     * 'binaryValue'. <br/>
     * NOTE: Trailing zeros '0' will be ignored.
     */
    this.setByBinaryString = function(binaryString) {
        binaryString = binaryString.replace(/0+$/, '');
        var unusedBits = 8 - binaryString.length % 8;
        if (unusedBits == 8) unusedBits = 0;
        for (var i = 0; i <= unusedBits; i++) {
            binaryString += '0';
        }
        var h = '';
        for (var i = 0; i < binaryString.length - 1; i += 8) {
            var b = binaryString.substr(i, 8);
            var x = parseInt(b, 2).toString(16);
            if (x.length == 1) x = '0' + x;
            h += x;  
        }
        this.hTLV = null;
        this.isModified = true;
        this.hV = '0' + unusedBits + h;
    };

    /**
     * set ASN.1 TLV value(V) by an array of boolean
     * @name setByBooleanArray
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {array} booleanArray array of boolean (ex. [true, false, true])
     * @description
     * NOTE: Trailing falses will be ignored.
     */
    this.setByBooleanArray = function(booleanArray) {
        var s = '';
        for (var i = 0; i < booleanArray.length; i++) {
            if (booleanArray[i] == true) {
                s += '1';
            } else {
                s += '0';
            }
        }
        this.setByBinaryString(s);
    };

    /**
     * generate an array of false with specified length
     * @name newFalseArray
     * @memberOf KJUR.asn1.DERBitString
     * @function
     * @param {Integer} nLength length of array to generate
     * @return {array} array of boolean faluse
     * @description
     * This static method may be useful to initialize boolean array.
     */
    this.newFalseArray = function(nLength) {
        var a = new Array(nLength);
        for (var i = 0; i < nLength; i++) {
            a[i] = false;
        }
        return a;
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params == "string" && params.toLowerCase().match(/^[0-9a-f]+$/)) {
            this.setHexValueIncludingUnusedBits(params);
        } else if (typeof params['hex'] != "undefined") {
            this.setHexValueIncludingUnusedBits(params['hex']);
        } else if (typeof params['bin'] != "undefined") {
            this.setByBinaryString(params['bin']);
        } else if (typeof params['array'] != "undefined") {
            this.setByBooleanArray(params['array']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER OctetString
 * @name KJUR.asn1.DEROctetString
 * @class class for ASN.1 DER OctetString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DEROctetString = function(params) {
    KJUR.asn1.DEROctetString.superclass.constructor.call(this, params);
    this.hT = "04";
};
YAHOO.lang.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER Null
 * @name KJUR.asn1.DERNull
 * @class class for ASN.1 DER Null
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @see KJUR.asn1.ASN1Object - superclass
 */
KJUR.asn1.DERNull = function() {
    KJUR.asn1.DERNull.superclass.constructor.call(this);
    this.hT = "05";
    this.hTLV = "0500";
};
YAHOO.lang.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER ObjectIdentifier
 * @name KJUR.asn1.DERObjectIdentifier
 * @class class for ASN.1 DER ObjectIdentifier
 * @param {Array} params associative array of parameters (ex. {'oid': '2.5.4.5'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>oid - specify initial ASN.1 value(V) by a oid string (ex. 2.5.4.13)</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERObjectIdentifier = function(params) {
    var itox = function(i) {
        var h = i.toString(16);
        if (h.length == 1) h = '0' + h;
        return h;
    };
    var roidtox = function(roid) {
        var h = '';
        var bi = new BigInteger(roid, 10);
        var b = bi.toString(2);
        var padLen = 7 - b.length % 7;
        if (padLen == 7) padLen = 0;
        var bPad = '';
        for (var i = 0; i < padLen; i++) bPad += '0';
        b = bPad + b;
        for (var i = 0; i < b.length - 1; i += 7) {
            var b8 = b.substr(i, 7);
            if (i != b.length - 7) b8 = '1' + b8;
            h += itox(parseInt(b8, 2));
        }
        return h;
    }

    KJUR.asn1.DERObjectIdentifier.superclass.constructor.call(this);
    this.hT = "06";

    /**
     * set value by a hexadecimal string
     * @name setValueHex
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} newHexString hexadecimal value of OID bytes
     */
    this.setValueHex = function(newHexString) {
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = newHexString;
    };

    /**
     * set value by a OID string
     * @name setValueOidString
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} oidString OID string (ex. 2.5.4.13)
     */
    this.setValueOidString = function(oidString) {
        if (! oidString.match(/^[0-9.]+$/)) {
            throw "malformed oid string: " + oidString;
        }
        var h = '';
        var a = oidString.split('.');
        var i0 = parseInt(a[0]) * 40 + parseInt(a[1]);
        h += itox(i0);
        a.splice(0, 2);
        for (var i = 0; i < a.length; i++) {
            h += roidtox(a[i]);
        }
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = h;
    };

    /**
     * set value by a OID name
     * @name setValueName
     * @memberOf KJUR.asn1.DERObjectIdentifier
     * @function
     * @param {String} oidName OID name (ex. 'serverAuth')
     * @since 1.0.1
     * @description
     * OID name shall be defined in 'KJUR.asn1.x509.OID.name2oidList'.
     * Otherwise raise error.
     */
    this.setValueName = function(oidName) {
        if (typeof KJUR.asn1.x509.OID.name2oidList[oidName] != "undefined") {
            var oid = KJUR.asn1.x509.OID.name2oidList[oidName];
            this.setValueOidString(oid);
        } else {
            throw "DERObjectIdentifier oidName undefined: " + oidName;
        }
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params == "string" && params.match(/^[0-2].[0-9.]+$/)) {
            this.setValueOidString(params);
        } else if (KJUR.asn1.x509.OID.name2oidList[params] !== undefined) {
            this.setValueOidString(KJUR.asn1.x509.OID.name2oidList[params]);
        } else if (typeof params['oid'] != "undefined") {
            this.setValueOidString(params['oid']);
        } else if (typeof params['hex'] != "undefined") {
            this.setValueHex(params['hex']);
        } else if (typeof params['name'] != "undefined") {
            this.setValueName(params['name']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER Enumerated
 * @name KJUR.asn1.DEREnumerated
 * @class class for ASN.1 DER Enumerated
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>int - specify initial ASN.1 value(V) by integer value</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DEREnumerated = function(params) {
    KJUR.asn1.DEREnumerated.superclass.constructor.call(this);
    this.hT = "0a";

    /**
     * set value by Tom Wu's BigInteger object
     * @name setByBigInteger
     * @memberOf KJUR.asn1.DEREnumerated
     * @function
     * @param {BigInteger} bigIntegerValue to set
     */
    this.setByBigInteger = function(bigIntegerValue) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(bigIntegerValue);
    };

    /**
     * set value by integer value
     * @name setByInteger
     * @memberOf KJUR.asn1.DEREnumerated
     * @function
     * @param {Integer} integer value to set
     */
    this.setByInteger = function(intValue) {
        var bi = new BigInteger(String(intValue), 10);
        this.setByBigInteger(bi);
    };

    /**
     * set value by integer value
     * @name setValueHex
     * @memberOf KJUR.asn1.DEREnumerated
     * @function
     * @param {String} hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     * @example
     * new KJUR.asn1.DEREnumerated(123);
     * new KJUR.asn1.DEREnumerated({'int': 123});
     * new KJUR.asn1.DEREnumerated({'hex': '1fad'});
     */
    this.setValueHex = function(newHexString) {
        this.hV = newHexString;
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params['int'] != "undefined") {
            this.setByInteger(params['int']);
        } else if (typeof params == "number") {
            this.setByInteger(params);
        } else if (typeof params['hex'] != "undefined") {
            this.setValueHex(params['hex']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DEREnumerated, KJUR.asn1.ASN1Object);

// ********************************************************************
/**
 * class for ASN.1 DER UTF8String
 * @name KJUR.asn1.DERUTF8String
 * @class class for ASN.1 DER UTF8String
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERUTF8String = function(params) {
    KJUR.asn1.DERUTF8String.superclass.constructor.call(this, params);
    this.hT = "0c";
};
YAHOO.lang.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER NumericString
 * @name KJUR.asn1.DERNumericString
 * @class class for ASN.1 DER NumericString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERNumericString = function(params) {
    KJUR.asn1.DERNumericString.superclass.constructor.call(this, params);
    this.hT = "12";
};
YAHOO.lang.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER PrintableString
 * @name KJUR.asn1.DERPrintableString
 * @class class for ASN.1 DER PrintableString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERPrintableString = function(params) {
    KJUR.asn1.DERPrintableString.superclass.constructor.call(this, params);
    this.hT = "13";
};
YAHOO.lang.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER TeletexString
 * @name KJUR.asn1.DERTeletexString
 * @class class for ASN.1 DER TeletexString
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERTeletexString = function(params) {
    KJUR.asn1.DERTeletexString.superclass.constructor.call(this, params);
    this.hT = "14";
};
YAHOO.lang.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER IA5String
 * @name KJUR.asn1.DERIA5String
 * @class class for ASN.1 DER IA5String
 * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
 * @extends KJUR.asn1.DERAbstractString
 * @description
 * @see KJUR.asn1.DERAbstractString - superclass
 */
KJUR.asn1.DERIA5String = function(params) {
    KJUR.asn1.DERIA5String.superclass.constructor.call(this, params);
    this.hT = "16";
};
YAHOO.lang.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);

// ********************************************************************
/**
 * class for ASN.1 DER UTCTime
 * @name KJUR.asn1.DERUTCTime
 * @class class for ASN.1 DER UTCTime
 * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
 * @extends KJUR.asn1.DERAbstractTime
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * <h4>EXAMPLES</h4>
 * @example
 * var d1 = new KJUR.asn1.DERUTCTime();
 * d1.setString('130430125959Z');
 *
 * var d2 = new KJUR.asn1.DERUTCTime({'str': '130430125959Z'});
 * var d3 = new KJUR.asn1.DERUTCTime({'date': new Date(Date.UTC(2015, 0, 31, 0, 0, 0, 0))});
 * var d4 = new KJUR.asn1.DERUTCTime('130430125959Z');
 */
KJUR.asn1.DERUTCTime = function(params) {
    KJUR.asn1.DERUTCTime.superclass.constructor.call(this, params);
    this.hT = "17";

    /**
     * set value by a Date object
     * @name setByDate
     * @memberOf KJUR.asn1.DERUTCTime
     * @function
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     */
    this.setByDate = function(dateObject) {
        this.hTLV = null;
        this.isModified = true;
        this.date = dateObject;
        this.s = this.formatDate(this.date, 'utc');
        this.hV = stohex(this.s);
    };

    this.getFreshValueHex = function() {
        if (typeof this.date == "undefined" && typeof this.s == "undefined") {
            this.date = new Date();
            this.s = this.formatDate(this.date, 'utc');
            this.hV = stohex(this.s);
        }
        return this.hV;
    };

    if (params !== undefined) {
        if (params.str !== undefined) {
            this.setString(params.str);
        } else if (typeof params == "string" && params.match(/^[0-9]{12}Z$/)) {
            this.setString(params);
        } else if (params.hex !== undefined) {
            this.setStringHex(params.hex);
        } else if (params.date !== undefined) {
            this.setByDate(params.date);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
/**
 * class for ASN.1 DER GeneralizedTime
 * @name KJUR.asn1.DERGeneralizedTime
 * @class class for ASN.1 DER GeneralizedTime
 * @param {Array} params associative array of parameters (ex. {'str': '20130430235959Z'})
 * @property {Boolean} withMillis flag to show milliseconds or not
 * @extends KJUR.asn1.DERAbstractTime
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'20130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * <li>millis - specify flag to show milliseconds (from 1.0.6)</li>
 * </ul>
 * NOTE1: 'params' can be omitted.
 * NOTE2: 'withMillis' property is supported from asn1 1.0.6.
 */
KJUR.asn1.DERGeneralizedTime = function(params) {
    KJUR.asn1.DERGeneralizedTime.superclass.constructor.call(this, params);
    this.hT = "18";
    this.withMillis = false;

    /**
     * set value by a Date object
     * @name setByDate
     * @memberOf KJUR.asn1.DERGeneralizedTime
     * @function
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     * @example
     * When you specify UTC time, use 'Date.UTC' method like this:<br/>
     * var o = new DERUTCTime();
     * var date = new Date(Date.UTC(2015, 0, 31, 23, 59, 59, 0)); #2015JAN31 23:59:59
     * o.setByDate(date);
     */
    this.setByDate = function(dateObject) {
        this.hTLV = null;
        this.isModified = true;
        this.date = dateObject;
        this.s = this.formatDate(this.date, 'gen', this.withMillis);
        this.hV = stohex(this.s);
    };

    this.getFreshValueHex = function() {
        if (this.date === undefined && this.s === undefined) {
            this.date = new Date();
            this.s = this.formatDate(this.date, 'gen', this.withMillis);
            this.hV = stohex(this.s);
        }
        return this.hV;
    };

    if (params !== undefined) {
        if (params.str !== undefined) {
            this.setString(params.str);
        } else if (typeof params == "string" && params.match(/^[0-9]{14}Z$/)) {
            this.setString(params);
        } else if (params.hex !== undefined) {
            this.setStringHex(params.hex);
        } else if (params.date !== undefined) {
            this.setByDate(params.date);
        }
        if (params.millis === true) {
            this.withMillis = true;
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
/**
 * class for ASN.1 DER Sequence
 * @name KJUR.asn1.DERSequence
 * @class class for ASN.1 DER Sequence
 * @extends KJUR.asn1.DERAbstractStructured
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
KJUR.asn1.DERSequence = function(params) {
    KJUR.asn1.DERSequence.superclass.constructor.call(this, params);
    this.hT = "30";
    this.getFreshValueHex = function() {
        var h = '';
        for (var i = 0; i < this.asn1Array.length; i++) {
            var asn1Obj = this.asn1Array[i];
            h += asn1Obj.getEncodedHex();
        }
        this.hV = h;
        return this.hV;
    };
};
YAHOO.lang.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
/**
 * class for ASN.1 DER Set
 * @name KJUR.asn1.DERSet
 * @class class for ASN.1 DER Set
 * @extends KJUR.asn1.DERAbstractStructured
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * <li>sortflag - flag for sort (default: true). ASN.1 BER is not sorted in 'SET OF'.</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: sortflag is supported since 1.0.5.
 */
KJUR.asn1.DERSet = function(params) {
    KJUR.asn1.DERSet.superclass.constructor.call(this, params);
    this.hT = "31";
    this.sortFlag = true; // item shall be sorted only in ASN.1 DER
    this.getFreshValueHex = function() {
        var a = new Array();
        for (var i = 0; i < this.asn1Array.length; i++) {
            var asn1Obj = this.asn1Array[i];
            a.push(asn1Obj.getEncodedHex());
        }
        if (this.sortFlag == true) a.sort();
        this.hV = a.join('');
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params.sortflag != "undefined" &&
            params.sortflag == false)
            this.sortFlag = false;
    }
};
YAHOO.lang.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
/**
 * class for ASN.1 DER TaggedObject
 * @name KJUR.asn1.DERTaggedObject
 * @class class for ASN.1 DER TaggedObject
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * Parameter 'tagNoNex' is ASN.1 tag(T) value for this object.
 * For example, if you find '[1]' tag in a ASN.1 dump, 
 * 'tagNoHex' will be 'a1'.
 * <br/>
 * As for optional argument 'params' for constructor, you can specify *ANY* of
 * following properties:
 * <ul>
 * <li>explicit - specify true if this is explicit tag otherwise false 
 *     (default is 'true').</li>
 * <li>tag - specify tag (default is 'a0' which means [0])</li>
 * <li>obj - specify ASN1Object which is tagged</li>
 * </ul>
 * @example
 * d1 = new KJUR.asn1.DERUTF8String({'str':'a'});
 * d2 = new KJUR.asn1.DERTaggedObject({'obj': d1});
 * hex = d2.getEncodedHex();
 */
KJUR.asn1.DERTaggedObject = function(params) {
    KJUR.asn1.DERTaggedObject.superclass.constructor.call(this);
    this.hT = "a0";
    this.hV = '';
    this.isExplicit = true;
    this.asn1Object = null;

    /**
     * set value by an ASN1Object
     * @name setString
     * @memberOf KJUR.asn1.DERTaggedObject
     * @function
     * @param {Boolean} isExplicitFlag flag for explicit/implicit tag
     * @param {Integer} tagNoHex hexadecimal string of ASN.1 tag
     * @param {ASN1Object} asn1Object ASN.1 to encapsulate
     */
    this.setASN1Object = function(isExplicitFlag, tagNoHex, asn1Object) {
        this.hT = tagNoHex;
        this.isExplicit = isExplicitFlag;
        this.asn1Object = asn1Object;
        if (this.isExplicit) {
            this.hV = this.asn1Object.getEncodedHex();
            this.hTLV = null;
            this.isModified = true;
        } else {
            this.hV = null;
            this.hTLV = asn1Object.getEncodedHex();
            this.hTLV = this.hTLV.replace(/^../, tagNoHex);
            this.isModified = false;
        }
    };

    this.getFreshValueHex = function() {
        return this.hV;
    };

    if (typeof params != "undefined") {
        if (typeof params['tag'] != "undefined") {
            this.hT = params['tag'];
        }
        if (typeof params['explicit'] != "undefined") {
            this.isExplicit = params['explicit'];
        }
        if (typeof params['obj'] != "undefined") {
            this.asn1Object = params['obj'];
            this.setASN1Object(this.isExplicit, this.hT, this.asn1Object);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);
/*! asn1x509-1.0.14.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * asn1x509.js - ASN.1 DER encoder classes for X.509 certificate
 *
 * Copyright (c) 2013-2015 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name asn1x509-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.14 (2016-May-10)
 * @since jsrsasign 2.1
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's ASN.1 class library name space
 * // already documented in asn1-1.0.js
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * kjur's ASN.1 class for X.509 certificate library name space
 * <p>
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily issue any kind of certificate</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * </p>
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link KJUR.asn1.x509.Certificate}</li>
 * <li>{@link KJUR.asn1.x509.TBSCertificate}</li>
 * <li>{@link KJUR.asn1.x509.Extension}</li>
 * <li>{@link KJUR.asn1.x509.X500Name}</li>
 * <li>{@link KJUR.asn1.x509.RDN}</li>
 * <li>{@link KJUR.asn1.x509.AttributeTypeAndValue}</li>
 * <li>{@link KJUR.asn1.x509.SubjectPublicKeyInfo}</li>
 * <li>{@link KJUR.asn1.x509.AlgorithmIdentifier}</li>
 * <li>{@link KJUR.asn1.x509.GeneralName}</li>
 * <li>{@link KJUR.asn1.x509.GeneralNames}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPointName}</li>
 * <li>{@link KJUR.asn1.x509.DistributionPoint}</li>
 * <li>{@link KJUR.asn1.x509.CRL}</li>
 * <li>{@link KJUR.asn1.x509.TBSCertList}</li>
 * <li>{@link KJUR.asn1.x509.CRLEntry}</li>
 * <li>{@link KJUR.asn1.x509.OID}</li>
 * </ul>
 * <h4>SUPPORTED EXTENSIONS</h4>
 * <ul>
 * <li>{@link KJUR.asn1.x509.BasicConstraints}</li>
 * <li>{@link KJUR.asn1.x509.KeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.CRLDistributionPoints}</li>
 * <li>{@link KJUR.asn1.x509.ExtKeyUsage}</li>
 * <li>{@link KJUR.asn1.x509.AuthorityKeyIdentifier}</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * @name KJUR.asn1.x509
 * @namespace
 */
if (typeof KJUR.asn1.x509 == "undefined" || !KJUR.asn1.x509) KJUR.asn1.x509 = {};

// === BEGIN Certificate ===================================================

/**
 * X.509 Certificate class to sign and generate hex encoded certificate
 * @name KJUR.asn1.x509.Certificate
 * @class X.509 Certificate class to sign and generate hex encoded certificate
 * @param {Array} params associative array of parameters (ex. {'tbscertobj': obj, 'prvkeyobj': key})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>tbscertobj - specify {@link KJUR.asn1.x509.TBSCertificate} object</li>
 * <li>prvkeyobj - specify {@link RSAKey}, {@link KJUR.crypto.ECDSA} or {@link KJUR.crypto.DSA} object for CA private key to sign the certificate</li>
 * <li>(DEPRECATED)rsaprvkey - specify {@link RSAKey} object CA private key</li>
 * <li>(DEPRECATED)rsaprvpem - specify PEM string of RSA CA private key</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: DSA/ECDSA is also supported for CA signging key from asn1x509 1.0.6.
 * @example
 * var caKey = KEYUTIL.getKey(caKeyPEM); // CA's private key
 * var cert = new KJUR.asn1x509.Certificate({'tbscertobj': tbs, 'prvkeyobj': caKey});
 * cert.sign(); // issue certificate by CA's private key
 * var certPEM = cert.getPEMString();
 *
 * // Certificate  ::=  SEQUENCE  {
 * //     tbsCertificate       TBSCertificate,
 * //     signatureAlgorithm   AlgorithmIdentifier,
 * //     signature            BIT STRING  }        
 */
KJUR.asn1.x509.Certificate = function(params) {
    KJUR.asn1.x509.Certificate.superclass.constructor.call(this);
    var asn1TBSCert = null;
    var asn1SignatureAlg = null;
    var asn1Sig = null;
    var hexSig = null;
    var prvKey = null;
    var rsaPrvKey = null; // DEPRECATED

    
    /**
     * set PKCS#5 encrypted RSA PEM private key as CA key
     * @name setRsaPrvKeyByPEMandPass
     * @memberOf KJUR.asn1.x509.Certificate
     * @function
     * @param {String} rsaPEM string of PKCS#5 encrypted RSA PEM private key
     * @param {String} passPEM passcode string to decrypt private key
     * @since 1.0.1
     * @description
     * <br/>
     * <h4>EXAMPLES</h4>
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs});
     * cert.setRsaPrvKeyByPEMandPass("-----BEGIN RSA PRIVATE..(snip)", "password");
     */
    this.setRsaPrvKeyByPEMandPass = function(rsaPEM, passPEM) {
        var caKeyHex = PKCS5PKEY.getDecryptedKeyHex(rsaPEM, passPEM);
        var caKey = new RSAKey();
        caKey.readPrivateKeyFromASN1HexString(caKeyHex);  
        this.prvKey = caKey;
    };

    /**
     * sign TBSCertificate and set signature value internally
     * @name sign
     * @memberOf KJUR.asn1.x509.Certificate
     * @function
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs, 'rsaprvkey': prvKey});
     * cert.sign();
     */
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;

        sig = new KJUR.crypto.Signature({'alg': 'SHA1withRSA'});
        sig.init(this.prvKey);
        sig.updateHex(this.asn1TBSCert.getEncodedHex());
        this.hexSig = sig.sign();

        this.asn1Sig = new KJUR.asn1.DERBitString({'hex': '00' + this.hexSig});
        
        var seq = new KJUR.asn1.DERSequence({'array': [this.asn1TBSCert,
                                                       this.asn1SignatureAlg,
                                                       this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    /**
     * set signature value internally by hex string
     * @name setSignatureHex
     * @memberOf KJUR.asn1.x509.Certificate
     * @function
     * @since asn1x509 1.0.8
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs});
     * cert.setSignatureHex('01020304');
     */
    this.setSignatureHex = function(sigHex) {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;
        this.hexSig = sigHex;
        this.asn1Sig = new KJUR.asn1.DERBitString({'hex': '00' + this.hexSig});

        var seq = new KJUR.asn1.DERSequence({'array': [this.asn1TBSCert,
                                                       this.asn1SignatureAlg,
                                                       this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) return this.hTLV;
        throw "not signed yet";
    };

    /**
     * get PEM formatted certificate string after signed
     * @name getPEMString
     * @memberOf KJUR.asn1.x509.Certificate
     * @function
     * @return PEM formatted string of certificate
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.Certificate({'tbscertobj': tbs, 'rsaprvkey': prvKey});
     * cert.sign();
     * var sPEM =  cert.getPEMString();
     */
    this.getPEMString = function() {
        var hCert = this.getEncodedHex();
        var wCert = CryptoJS.enc.Hex.parse(hCert);
        var b64Cert = CryptoJS.enc.Base64.stringify(wCert);
        var pemBody = b64Cert.replace(/(.{64})/g, "$1\r\n");
        return "-----BEGIN CERTIFICATE-----\r\n" + pemBody + "\r\n-----END CERTIFICATE-----\r\n";
    };

    if (typeof params != "undefined") {
        if (typeof params['tbscertobj'] != "undefined") {
            this.asn1TBSCert = params['tbscertobj'];
        }
        if (typeof params['prvkeyobj'] != "undefined") {
            this.prvKey = params['prvkeyobj'];
        } else if (typeof params['rsaprvkey'] != "undefined") {
            this.prvKey = params['rsaprvkey'];
        } else if ((typeof params['rsaprvpem'] != "undefined") &&
                   (typeof params['rsaprvpas'] != "undefined")) {
            this.setRsaPrvKeyByPEMandPass(params['rsaprvpem'], params['rsaprvpas']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Certificate, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertificate structure class
 * @name KJUR.asn1.x509.TBSCertificate
 * @class ASN.1 TBSCertificate structure class
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * <h4>EXAMPLE</h4>
 * @example
 *  var o = new KJUR.asn1.x509.TBSCertificate();
 *  o.setSerialNumberByParam({'int': 4});
 *  o.setSignatureAlgByParam({'name': 'SHA1withRSA'});
 *  o.setIssuerByParam({'str': '/C=US/O=a'});
 *  o.setNotBeforeByParam({'str': '130504235959Z'});
 *  o.setNotAfterByParam({'str': '140504235959Z'});
 *  o.setSubjectByParam({'str': '/C=US/CN=b'});
 *  o.setSubjectPublicKeyByParam({'rsakey': rsaKey});
 *  o.appendExtension(new KJUR.asn1.x509.BasicConstraints({'cA':true}));
 *  o.appendExtension(new KJUR.asn1.x509.KeyUsage({'bin':'11'}));
 */
KJUR.asn1.x509.TBSCertificate = function(params) {
    KJUR.asn1.x509.TBSCertificate.superclass.constructor.call(this);

    this._initialize = function() {
        this.asn1Array = new Array();

        this.asn1Version = 
            new KJUR.asn1.DERTaggedObject({'obj': new KJUR.asn1.DERInteger({'int': 2})});
        this.asn1SerialNumber = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1NotBefore = null;
        this.asn1NotAfter = null;
        this.asn1Subject = null;
        this.asn1SubjPKey = null;
        this.extensionsArray = new Array();
    };

    /**
     * set serial number field by parameter
     * @name setSerialNumberByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} intParam DERInteger param
     * @description
     * @example
     * tbsc.setSerialNumberByParam({'int': 3});
     */
    this.setSerialNumberByParam = function(intParam) {
        this.asn1SerialNumber = new KJUR.asn1.DERInteger(intParam);
    };

    /**
     * set signature algorithm field by parameter
     * @name setSignatureAlgByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} algIdParam AlgorithmIdentifier parameter
     * @description
     * @example
     * tbsc.setSignatureAlgByParam({'name': 'SHA1withRSA'});
     */
    this.setSignatureAlgByParam = function(algIdParam) {
        this.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier(algIdParam);
    };

    /**
     * set issuer name field by parameter
     * @name setIssuerByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setIssuerParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setIssuerByParam = function(x500NameParam) {
        this.asn1Issuer = new KJUR.asn1.x509.X500Name(x500NameParam);
    };

    /**
     * set notBefore field by parameter
     * @name setNotBeforeByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNotBeforeByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNotBeforeByParam = function(timeParam) {
        this.asn1NotBefore = new KJUR.asn1.x509.Time(timeParam);
    };
    
    /**
     * set notAfter field by parameter
     * @name setNotAfterByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNotAfterByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNotAfterByParam = function(timeParam) {
        this.asn1NotAfter = new KJUR.asn1.x509.Time(timeParam);
    };

    /**
     * set subject name field by parameter
     * @name setSubjectByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setSubjectParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setSubjectByParam = function(x500NameParam) {
        this.asn1Subject = new KJUR.asn1.x509.X500Name(x500NameParam);
    };

    /**
     * (DEPRECATED) set subject public key info field by RSA key parameter
     * @name setSubjectPublicKeyByParam
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Array} subjPKeyParam SubjectPublicKeyInfo parameter of RSA
     * @deprecated
     * @description
     * @example
     * tbsc.setSubjectPublicKeyByParam({'rsakey': pubKey});
     * @see KJUR.asn1.x509.SubjectPublicKeyInfo
     */
    this.setSubjectPublicKeyByParam = function(subjPKeyParam) {
        this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(subjPKeyParam);
    };

    /**
     * set subject public key info by RSA/ECDSA/DSA key parameter
     * @name setSubjectPublicKeyByGetKey
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Object} keyParam public key parameter which passed to {@link KEYUTIL.getKey} argument
     * @description
     * @example
     * tbsc.setSubjectPublicKeyByGetKeyParam(certPEMString); // or 
     * tbsc.setSubjectPublicKeyByGetKeyParam(pkcs8PublicKeyPEMString); // or 
     * tbsc.setSubjectPublicKeyByGetKeyParam(kjurCryptoECDSAKeyObject); // et.al.
     * @see KJUR.asn1.x509.SubjectPublicKeyInfo
     * @see KEYUTIL.getKey
     * @since asn1x509 1.0.6
     */
    this.setSubjectPublicKeyByGetKey = function(keyParam) {
        var keyObj = KEYUTIL.getKey(keyParam);
        this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(keyObj);
    };

    /**
     * append X.509v3 extension to this object
     * @name appendExtension
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {Extension} extObj X.509v3 Extension object
     * @description
     * @example
     * tbsc.appendExtension(new KJUR.asn1.x509.BasicConstraints({'cA':true, 'critical': true}));
     * tbsc.appendExtension(new KJUR.asn1.x509.KeyUsage({'bin':'11'}));
     * @see KJUR.asn1.x509.Extension
     */
    this.appendExtension = function(extObj) {
        this.extensionsArray.push(extObj);
    };

    /**
     * append X.509v3 extension to this object by name and parameters
     * @name appendExtensionByName
     * @memberOf KJUR.asn1.x509.TBSCertificate
     * @function
     * @param {name} name name of X.509v3 Extension object
     * @param {Array} extParams parameters as argument of Extension constructor.
     * @description
     * @example
     * tbsc.appendExtensionByName('BasicConstraints', {'cA':true, 'critical': true});
     * tbsc.appendExtensionByName('KeyUsage', {'bin':'11'});
     * tbsc.appendExtensionByName('CRLDistributionPoints', {uri: 'http://aaa.com/a.crl'});
     * tbsc.appendExtensionByName('ExtKeyUsage', {array: [{name: 'clientAuth'}]});
     * tbsc.appendExtensionByName('AuthorityKeyIdentifier', {kid: '1234ab..'});
     * @see KJUR.asn1.x509.Extension
     */
    this.appendExtensionByName = function(name, extParams) {
        if (name.toLowerCase() == "basicconstraints") {
            var extObj = new KJUR.asn1.x509.BasicConstraints(extParams);
            this.appendExtension(extObj);
        } else if (name.toLowerCase() == "keyusage") {
            var extObj = new KJUR.asn1.x509.KeyUsage(extParams);
            this.appendExtension(extObj);
        } else if (name.toLowerCase() == "crldistributionpoints") {
            var extObj = new KJUR.asn1.x509.CRLDistributionPoints(extParams);
            this.appendExtension(extObj);
        } else if (name.toLowerCase() == "extkeyusage") {
            var extObj = new KJUR.asn1.x509.ExtKeyUsage(extParams);
            this.appendExtension(extObj);
        } else if (name.toLowerCase() == "authoritykeyidentifier") {
            var extObj = new KJUR.asn1.x509.AuthorityKeyIdentifier(extParams);
            this.appendExtension(extObj);
        } else {
            throw "unsupported extension name: " + name;
        }
    };

    this.getEncodedHex = function() {
        if (this.asn1NotBefore == null || this.asn1NotAfter == null)
            throw "notBefore and/or notAfter not set";
        var asn1Validity = 
            new KJUR.asn1.DERSequence({'array':[this.asn1NotBefore, this.asn1NotAfter]});

        this.asn1Array = new Array();

        this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1SerialNumber);
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(asn1Validity);
        this.asn1Array.push(this.asn1Subject);
        this.asn1Array.push(this.asn1SubjPKey);

        if (this.extensionsArray.length > 0) {
            var extSeq = new KJUR.asn1.DERSequence({"array": this.extensionsArray});
            var extTagObj = new KJUR.asn1.DERTaggedObject({'explicit': true,
                                                           'tag': 'a3',
                                                           'obj': extSeq});
            this.asn1Array.push(extTagObj);
        }

        var o = new KJUR.asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        this.isModified = false;
        return this.hTLV;
    };

    this._initialize();
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertificate, KJUR.asn1.ASN1Object);

// === END   TBSCertificate ===================================================

// === BEGIN X.509v3 Extensions Related =======================================

/**
 * base Extension ASN.1 structure class
 * @name KJUR.asn1.x509.Extension
 * @class base Extension ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'critical': true})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 * // Extension  ::=  SEQUENCE  {
 * //     extnID      OBJECT IDENTIFIER,
 * //     critical    BOOLEAN DEFAULT FALSE,
 * //     extnValue   OCTET STRING  }
 */
KJUR.asn1.x509.Extension = function(params) {
    KJUR.asn1.x509.Extension.superclass.constructor.call(this);
    var asn1ExtnValue = null;

    this.getEncodedHex = function() {
        var asn1Oid = new KJUR.asn1.DERObjectIdentifier({'oid': this.oid});
        var asn1EncapExtnValue = 
            new KJUR.asn1.DEROctetString({'hex': this.getExtnValueHex()});

        var asn1Array = new Array();
        asn1Array.push(asn1Oid);
        if (this.critical) asn1Array.push(new KJUR.asn1.DERBoolean());
        asn1Array.push(asn1EncapExtnValue);

        var asn1Seq = new KJUR.asn1.DERSequence({'array': asn1Array});
        return asn1Seq.getEncodedHex();
    };

    this.critical = false;
    if (typeof params != "undefined") {
        if (typeof params['critical'] != "undefined") {
            this.critical = params['critical'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Extension, KJUR.asn1.ASN1Object);

/**
 * KeyUsage ASN.1 structure class
 * @name KJUR.asn1.x509.KeyUsage
 * @class KeyUsage ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'bin': '11', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 */
KJUR.asn1.x509.KeyUsage = function(params) {
    KJUR.asn1.x509.KeyUsage.superclass.constructor.call(this, params);

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.15";
    if (typeof params != "undefined") {
        if (typeof params['bin'] != "undefined") {
            this.asn1ExtnValue = new KJUR.asn1.DERBitString(params);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.KeyUsage, KJUR.asn1.x509.Extension);

/**
 * BasicConstraints ASN.1 structure class
 * @name KJUR.asn1.x509.BasicConstraints
 * @class BasicConstraints ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'cA': true, 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 */
KJUR.asn1.x509.BasicConstraints = function(params) {
    KJUR.asn1.x509.BasicConstraints.superclass.constructor.call(this, params);
    var cA = false;
    var pathLen = -1;

    this.getExtnValueHex = function() {
        var asn1Array = new Array();
        if (this.cA) asn1Array.push(new KJUR.asn1.DERBoolean());
        if (this.pathLen > -1) 
            asn1Array.push(new KJUR.asn1.DERInteger({'int': this.pathLen}));
        var asn1Seq = new KJUR.asn1.DERSequence({'array': asn1Array});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.19";
    this.cA = false;
    this.pathLen = -1;
    if (typeof params != "undefined") {
        if (typeof params['cA'] != "undefined") {
            this.cA = params['cA'];
        }
        if (typeof params['pathLen'] != "undefined") {
            this.pathLen = params['pathLen'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.BasicConstraints, KJUR.asn1.x509.Extension);

/**
 * CRLDistributionPoints ASN.1 structure class
 * @name KJUR.asn1.x509.CRLDistributionPoints
 * @class CRLDistributionPoints ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'uri': 'http://a.com/', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 */
KJUR.asn1.x509.CRLDistributionPoints = function(params) {
    KJUR.asn1.x509.CRLDistributionPoints.superclass.constructor.call(this, params);

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.setByDPArray = function(dpArray) {
        this.asn1ExtnValue = new KJUR.asn1.DERSequence({'array': dpArray});
    };

    this.setByOneURI = function(uri) {
        var gn1 = new KJUR.asn1.x509.GeneralNames([{'uri': uri}]);
        var dpn1 = new KJUR.asn1.x509.DistributionPointName(gn1);
        var dp1 = new KJUR.asn1.x509.DistributionPoint({'dpobj': dpn1});
        this.setByDPArray([dp1]);
    };

    this.oid = "2.5.29.31";
    if (typeof params != "undefined") {
        if (typeof params['array'] != "undefined") {
            this.setByDPArray(params['array']);
        } else if (typeof params['uri'] != "undefined") {
            this.setByOneURI(params['uri']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRLDistributionPoints, KJUR.asn1.x509.Extension);

/**
 * KeyUsage ASN.1 structure class
 * @name KJUR.asn1.x509.ExtKeyUsage
 * @class ExtKeyUsage ASN.1 structure class
 * @param {Array} params associative array of parameters
 * @extends KJUR.asn1.x509.Extension
 * @description
 * @example
 * var e1 = 
 *     new KJUR.asn1.x509.ExtKeyUsage({'critical': true,
 *                                     'array':
 *                                     [{'oid': '2.5.29.37.0',  // anyExtendedKeyUsage
 *                                       'name': 'clientAuth'}]});
 *
 * // id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 * // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * // KeyPurposeId ::= OBJECT IDENTIFIER
 */
KJUR.asn1.x509.ExtKeyUsage = function(params) {
    KJUR.asn1.x509.ExtKeyUsage.superclass.constructor.call(this, params);

    this.setPurposeArray = function(purposeArray) {
        this.asn1ExtnValue = new KJUR.asn1.DERSequence();
        for (var i = 0; i < purposeArray.length; i++) {
            var o = new KJUR.asn1.DERObjectIdentifier(purposeArray[i]);
            this.asn1ExtnValue.appendASN1Object(o);
        }
    };

    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex();
    };

    this.oid = "2.5.29.37";
    if (typeof params != "undefined") {
        if (typeof params['array'] != "undefined") {
            this.setPurposeArray(params['array']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.ExtKeyUsage, KJUR.asn1.x509.Extension);

/**
 * AuthorityKeyIdentifier ASN.1 structure class
 * @name KJUR.asn1.x509.AuthorityKeyIdentifier
 * @class AuthorityKeyIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'uri': 'http://a.com/', 'critical': true})
 * @extends KJUR.asn1.x509.Extension
 * @since asn1x509 1.0.8
 * @description
 * <pre>
 * d-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 * KeyIdentifier ::= OCTET STRING
 * </pre>
 * @example
 * var param = {'kid': {'hex': '89ab'},
 *              'issuer': {'str': '/C=US/CN=a'},
 *              'sn': {'hex': '1234'},
 *              'critical': true});
 * var e1 = new KJUR.asn1.x509.AuthorityKeyIdentifier(param);
 */
KJUR.asn1.x509.AuthorityKeyIdentifier = function(params) {
    KJUR.asn1.x509.AuthorityKeyIdentifier.superclass.constructor.call(this, params);
    this.asn1KID = null;
    this.asn1CertIssuer = null;
    this.asn1CertSN = null;

    this.getExtnValueHex = function() {
        var a = new Array();
        if (this.asn1KID)
            a.push(new KJUR.asn1.DERTaggedObject({'explicit': false,
                                                  'tag': '80',
                                                  'obj': this.asn1KID}));
        if (this.asn1CertIssuer)
            a.push(new KJUR.asn1.DERTaggedObject({'explicit': false,
                                                  'tag': 'a1',
                                                  'obj': this.asn1CertIssuer}));
        if (this.asn1CertSN)
            a.push(new KJUR.asn1.DERTaggedObject({'explicit': false,
                                                  'tag': '82',
                                                  'obj': this.asn1CertSN}));

        var asn1Seq = new KJUR.asn1.DERSequence({'array': a});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.getEncodedHex();
    };

    /**
     * set keyIdentifier value by DERInteger parameter
     * @name setKIDByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier
     * @function
     * @param {Array} param array of {@link KJUR.asn1.DERInteger} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic keyIdentifier value calculation by an issuer 
     * public key will be supported in future version.
     */
    this.setKIDByParam = function(param) {
        this.asn1KID = new KJUR.asn1.DEROctetString(param);
    };

    /**
     * set authorityCertIssuer value by X500Name parameter
     * @name setCertIssuerByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier
     * @function
     * @param {Array} param array of {@link KJUR.asn1.x509.X500Name} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic authorityCertIssuer name setting by an issuer 
     * certificate will be supported in future version.
     */
    this.setCertIssuerByParam = function(param) {
        this.asn1CertIssuer = new KJUR.asn1.x509.X500Name(param);
    };

    /**
     * set authorityCertSerialNumber value by DERInteger parameter
     * @name setCertSerialNumberByParam
     * @memberOf KJUR.asn1.x509.AuthorityKeyIdentifier
     * @function
     * @param {Array} param array of {@link KJUR.asn1.DERInteger} parameter
     * @since asn1x509 1.0.8
     * @description
     * NOTE: Automatic authorityCertSerialNumber setting by an issuer 
     * certificate will be supported in future version.
     */
    this.setCertSNByParam = function(param) {
        this.asn1CertSN = new KJUR.asn1.DERInteger(param);
    };

    this.oid = "2.5.29.35";
    if (typeof params != "undefined") {
        if (typeof params['kid'] != "undefined") {
            this.setKIDByParam(params['kid']);
        }
        if (typeof params['issuer'] != "undefined") {
            this.setCertIssuerByParam(params['issuer']);
        }
        if (typeof params['sn'] != "undefined") {
            this.setCertSNByParam(params['sn']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AuthorityKeyIdentifier, KJUR.asn1.x509.Extension);

// === END   X.509v3 Extensions Related =======================================

// === BEGIN CRL Related ===================================================
/**
 * X.509 CRL class to sign and generate hex encoded CRL
 * @name KJUR.asn1.x509.CRL
 * @class X.509 CRL class to sign and generate hex encoded certificate
 * @param {Array} params associative array of parameters (ex. {'tbsobj': obj, 'rsaprvkey': key})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>tbsobj - specify {@link KJUR.asn1.x509.TBSCertList} object to be signed</li>
 * <li>rsaprvkey - specify {@link RSAKey} object CA private key</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * <h4>EXAMPLE</h4>
 * @example
 * var prvKey = new RSAKey(); // CA's private key
 * prvKey.readPrivateKeyFromASN1HexString("3080...");
 * var crl = new KJUR.asn1x509.CRL({'tbsobj': tbs, 'rsaprvkey': prvKey});
 * crl.sign(); // issue CRL by CA's private key
 * var hCRL = crl.getEncodedHex();
 *
 * // CertificateList  ::=  SEQUENCE  {
 * //     tbsCertList          TBSCertList,
 * //     signatureAlgorithm   AlgorithmIdentifier,
 * //     signatureValue       BIT STRING  }
 */
KJUR.asn1.x509.CRL = function(params) {
    KJUR.asn1.x509.CRL.superclass.constructor.call(this);

    var asn1TBSCertList = null;
    var asn1SignatureAlg = null;
    var asn1Sig = null;
    var hexSig = null;
    var rsaPrvKey = null;
    
    /**
     * set PKCS#5 encrypted RSA PEM private key as CA key
     * @name setRsaPrvKeyByPEMandPass
     * @memberOf KJUR.asn1.x509.CRL
     * @function
     * @param {String} rsaPEM string of PKCS#5 encrypted RSA PEM private key
     * @param {String} passPEM passcode string to decrypt private key
     * @description
     * <br/>
     * <h4>EXAMPLES</h4>
     * @example
     */
    this.setRsaPrvKeyByPEMandPass = function(rsaPEM, passPEM) {
        var caKeyHex = PKCS5PKEY.getDecryptedKeyHex(rsaPEM, passPEM);
        var caKey = new RSAKey();
        caKey.readPrivateKeyFromASN1HexString(caKeyHex);  
        this.rsaPrvKey = caKey;
    };

    /**
     * sign TBSCertList and set signature value internally
     * @name sign
     * @memberOf KJUR.asn1.x509.CRL
     * @function
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.CRL({'tbsobj': tbs, 'rsaprvkey': prvKey});
     * cert.sign();
     */
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCertList.asn1SignatureAlg;

        sig = new KJUR.crypto.Signature({'alg': 'SHA1withRSA', 'prov': 'cryptojs/jsrsa'});
        sig.initSign(this.rsaPrvKey);
        sig.updateHex(this.asn1TBSCertList.getEncodedHex());
        this.hexSig = sig.sign();

        this.asn1Sig = new KJUR.asn1.DERBitString({'hex': '00' + this.hexSig});
        
        var seq = new KJUR.asn1.DERSequence({'array': [this.asn1TBSCertList,
                                                       this.asn1SignatureAlg,
                                                       this.asn1Sig]});
        this.hTLV = seq.getEncodedHex();
        this.isModified = false;
    };

    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) return this.hTLV;
        throw "not signed yet";
    };

    /**
     * get PEM formatted CRL string after signed
     * @name getPEMString
     * @memberOf KJUR.asn1.x509.CRL
     * @function
     * @return PEM formatted string of certificate
     * @description
     * @example
     * var cert = new KJUR.asn1.x509.CRL({'tbsobj': tbs, 'rsaprvkey': prvKey});
     * cert.sign();
     * var sPEM =  cert.getPEMString();
     */
    this.getPEMString = function() {
        var hCert = this.getEncodedHex();
        var wCert = CryptoJS.enc.Hex.parse(hCert);
        var b64Cert = CryptoJS.enc.Base64.stringify(wCert);
        var pemBody = b64Cert.replace(/(.{64})/g, "$1\r\n");
        return "-----BEGIN X509 CRL-----\r\n" + pemBody + "\r\n-----END X509 CRL-----\r\n";
    };

    if (typeof params != "undefined") {
        if (typeof params['tbsobj'] != "undefined") {
            this.asn1TBSCertList = params['tbsobj'];
        }
        if (typeof params['rsaprvkey'] != "undefined") {
            this.rsaPrvKey = params['rsaprvkey'];
        }
        if ((typeof params['rsaprvpem'] != "undefined") &&
            (typeof params['rsaprvpas'] != "undefined")) {
            this.setRsaPrvKeyByPEMandPass(params['rsaprvpem'], params['rsaprvpas']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRL, KJUR.asn1.ASN1Object);

/**
 * ASN.1 TBSCertList structure class for CRL
 * @name KJUR.asn1.x509.TBSCertList
 * @class ASN.1 TBSCertList structure class for CRL
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * <br/>
 * <h4>EXAMPLE</h4>
 * @example
 *  var o = new KJUR.asn1.x509.TBSCertList();
 *  o.setSignatureAlgByParam({'name': 'SHA1withRSA'});
 *  o.setIssuerByParam({'str': '/C=US/O=a'});
 *  o.setNotThisUpdateByParam({'str': '130504235959Z'});
 *  o.setNotNextUpdateByParam({'str': '140504235959Z'});
 *  o.addRevokedCert({'int': 4}, {'str':'130514235959Z'}));
 *  o.addRevokedCert({'hex': '0f34dd'}, {'str':'130514235959Z'}));
 * 
 * // TBSCertList  ::=  SEQUENCE  {
 * //        version                 Version OPTIONAL,
 * //                                     -- if present, MUST be v2
 * //        signature               AlgorithmIdentifier,
 * //        issuer                  Name,
 * //        thisUpdate              Time,
 * //        nextUpdate              Time OPTIONAL,
 * //        revokedCertificates     SEQUENCE OF SEQUENCE  {
 * //             userCertificate         CertificateSerialNumber,
 * //             revocationDate          Time,
 * //             crlEntryExtensions      Extensions OPTIONAL
 * //                                      -- if present, version MUST be v2
 * //                                  }  OPTIONAL,
 * //        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 */
KJUR.asn1.x509.TBSCertList = function(params) {
    KJUR.asn1.x509.TBSCertList.superclass.constructor.call(this);
    var aRevokedCert = null;

    /**
     * set signature algorithm field by parameter
     * @name setSignatureAlgByParam
     * @memberOf KJUR.asn1.x509.TBSCertList
     * @function
     * @param {Array} algIdParam AlgorithmIdentifier parameter
     * @description
     * @example
     * tbsc.setSignatureAlgByParam({'name': 'SHA1withRSA'});
     */
    this.setSignatureAlgByParam = function(algIdParam) {
        this.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier(algIdParam);
    };

    /**
     * set issuer name field by parameter
     * @name setIssuerByParam
     * @memberOf KJUR.asn1.x509.TBSCertList
     * @function
     * @param {Array} x500NameParam X500Name parameter
     * @description
     * @example
     * tbsc.setIssuerParam({'str': '/C=US/CN=b'});
     * @see KJUR.asn1.x509.X500Name
     */
    this.setIssuerByParam = function(x500NameParam) {
        this.asn1Issuer = new KJUR.asn1.x509.X500Name(x500NameParam);
    };

    /**
     * set thisUpdate field by parameter
     * @name setThisUpdateByParam
     * @memberOf KJUR.asn1.x509.TBSCertList
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setThisUpdateByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setThisUpdateByParam = function(timeParam) {
        this.asn1ThisUpdate = new KJUR.asn1.x509.Time(timeParam);
    };

    /**
     * set nextUpdate field by parameter
     * @name setNextUpdateByParam
     * @memberOf KJUR.asn1.x509.TBSCertList
     * @function
     * @param {Array} timeParam Time parameter
     * @description
     * @example
     * tbsc.setNextUpdateByParam({'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.setNextUpdateByParam = function(timeParam) {
        this.asn1NextUpdate = new KJUR.asn1.x509.Time(timeParam);
    };

    /**
     * add revoked certficate by parameter
     * @name addRevokedCert
     * @memberOf KJUR.asn1.x509.TBSCertList
     * @function
     * @param {Array} snParam DERInteger parameter for certificate serial number
     * @param {Array} timeParam Time parameter for revocation date
     * @description
     * @example
     * tbsc.addRevokedCert({'int': 3}, {'str': '130508235959Z'});
     * @see KJUR.asn1.x509.Time
     */
    this.addRevokedCert = function(snParam, timeParam) {
        var param = {};
        if (snParam != undefined && snParam != null) param['sn'] = snParam;
        if (timeParam != undefined && timeParam != null) param['time'] = timeParam;
        var o = new KJUR.asn1.x509.CRLEntry(param);
        this.aRevokedCert.push(o);
    };

    this.getEncodedHex = function() {
        this.asn1Array = new Array();

        if (this.asn1Version != null) this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(this.asn1ThisUpdate);
        if (this.asn1NextUpdate != null) this.asn1Array.push(this.asn1NextUpdate);

        if (this.aRevokedCert.length > 0) {
            var seq = new KJUR.asn1.DERSequence({'array': this.aRevokedCert});
            this.asn1Array.push(seq);
        }

        var o = new KJUR.asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        this.isModified = false;
        return this.hTLV;
    };

    this._initialize = function() {
        this.asn1Version = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1ThisUpdate = null;
        this.asn1NextUpdate = null;
        this.aRevokedCert = new Array();
    };

    this._initialize();
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertList, KJUR.asn1.ASN1Object);

/**
 * ASN.1 CRLEntry structure class for CRL
 * @name KJUR.asn1.x509.CRLEntry
 * @class ASN.1 CRLEntry structure class for CRL
 * @param {Array} params associative array of parameters (ex. {})
 * @extends KJUR.asn1.ASN1Object
 * @since 1.0.3
 * @description
 * @example
 * var e = new KJUR.asn1.x509.CRLEntry({'time': {'str': '130514235959Z'}, 'sn': {'int': 234}});
 * 
 * // revokedCertificates     SEQUENCE OF SEQUENCE  {
 * //     userCertificate         CertificateSerialNumber,
 * //     revocationDate          Time,
 * //     crlEntryExtensions      Extensions OPTIONAL
 * //                             -- if present, version MUST be v2 }
 */
KJUR.asn1.x509.CRLEntry = function(params) {
    KJUR.asn1.x509.CRLEntry.superclass.constructor.call(this);
    var sn = null;
    var time = null;

    /**
     * set DERInteger parameter for serial number of revoked certificate 
     * @name setCertSerial
     * @memberOf KJUR.asn1.x509.CRLEntry
     * @function
     * @param {Array} intParam DERInteger parameter for certificate serial number
     * @description
     * @example
     * entry.setCertSerial({'int': 3});
     */
    this.setCertSerial = function(intParam) {
        this.sn = new KJUR.asn1.DERInteger(intParam);
    };

    /**
     * set Time parameter for revocation date
     * @name setRevocationDate
     * @memberOf KJUR.asn1.x509.CRLEntry
     * @function
     * @param {Array} timeParam Time parameter for revocation date
     * @description
     * @example
     * entry.setRevocationDate({'str': '130508235959Z'});
     */
    this.setRevocationDate = function(timeParam) {
        this.time = new KJUR.asn1.x509.Time(timeParam);
    };

    this.getEncodedHex = function() {
        var o = new KJUR.asn1.DERSequence({"array": [this.sn, this.time]});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };
    
    if (typeof params != "undefined") {
        if (typeof params['time'] != "undefined") {
            this.setRevocationDate(params['time']);
        }
        if (typeof params['sn'] != "undefined") {
            this.setCertSerial(params['sn']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRLEntry, KJUR.asn1.ASN1Object);

// === END   CRL Related ===================================================

// === BEGIN X500Name Related =================================================
/**
 * X500Name ASN.1 structure class
 * @name KJUR.asn1.x509.X500Name
 * @class X500Name ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': '/C=US/O=a'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 * // 1. construct with string
 * o = new KJUR.asn1.x509.X500Name({str: "/C=US/O=aaa/OU=bbb/CN=foo@example.com"});
 * // 2. construct by object
 * o = new KJUR.asn1.x509.X500Name({C: "US", O: "aaa", CN: "http://example.com/"});
 */
KJUR.asn1.x509.X500Name = function(params) {
    KJUR.asn1.x509.X500Name.superclass.constructor.call(this);
    this.asn1Array = new Array();

    /**
     * set DN by string
     * @name setByString
     * @memberOf KJUR.asn1.x509.X500Name
     * @function
     * @param {Array} dnStr distinguished name by string (ex. /C=US/O=aaa)
     * @description
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByString("/C=US/O=aaa/OU=bbb/CN=foo@example.com");
     */
    this.setByString = function(dnStr) {
        var a = dnStr.split('/');
        a.shift();
        for (var i = 0; i < a.length; i++) {
            this.asn1Array.push(new KJUR.asn1.x509.RDN({'str':a[i]}));
        }
    };
    
    /**
     * set DN by associative array
     * @name setByObject
     * @memberOf KJUR.asn1.x509.X500Name
     * @function
     * @param {Array} dnObj associative array of DN (ex. {C: "US", O: "aaa"})
     * @since jsrsasign 4.9. asn1x509 1.0.13
     * @description
     * @example
     * name = new KJUR.asn1.x509.X500Name();
     * name.setByObject({C: "US", O: "aaa", CN="http://example.com/"1});
     */
    this.setByObject = function(dnObj) {
        // Get all the dnObject attributes and stuff them in the ASN.1 array.
        for (var x in dnObj) {
            if (dnObj.hasOwnProperty(x)) {
                var newRDN = new KJUR.asn1.x509.RDN(
                    {'str': x + '=' + dnObj[x]});
                // Initialize or push into the ANS1 array.
                this.asn1Array ? this.asn1Array.push(newRDN)
                    : this.asn1Array = [newRDN];
            }
        }
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        var o = new KJUR.asn1.DERSequence({"array": this.asn1Array});
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params['str'] != "undefined") {
            this.setByString(params['str']);
        // If params is an object, then set the ASN1 array just using the object
        // attributes. This is nice for fields that have lots of special
        // characters (i.e. CN: 'http://www.github.com/kjur//').
        } else if (typeof params === "object") {
            this.setByObject(params);
        }
        
        if (typeof params.certissuer != "undefined") {
            var x = new X509();
            x.hex = X509.pemToHex(params.certissuer);
            this.hTLV = x.getIssuerHex();
        }
        if (typeof params.certsubject != "undefined") {
            var x = new X509();
            x.hex = X509.pemToHex(params.certsubject);
            this.hTLV = x.getSubjectHex();
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.X500Name, KJUR.asn1.ASN1Object);

/**
 * RDN (Relative Distinguish Name) ASN.1 structure class
 * @name KJUR.asn1.x509.RDN
 * @class RDN (Relative Distinguish Name) ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': 'C=US'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 */
KJUR.asn1.x509.RDN = function(params) {
    KJUR.asn1.x509.RDN.superclass.constructor.call(this);
    this.asn1Array = new Array();

    this.addByString = function(rdnStr) {
        this.asn1Array.push(new KJUR.asn1.x509.AttributeTypeAndValue({'str':rdnStr}));
    };

    this.getEncodedHex = function() {
        var o = new KJUR.asn1.DERSet({"array": this.asn1Array});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

    if (typeof params != "undefined") {
        if (typeof params['str'] != "undefined") {
            this.addByString(params['str']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.RDN, KJUR.asn1.ASN1Object);

/**
 * AttributeTypeAndValue ASN.1 structure class
 * @name KJUR.asn1.x509.AttributeTypeAndValue
 * @class AttributeTypeAndValue ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': 'C=US'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 */
KJUR.asn1.x509.AttributeTypeAndValue = function(params) {
    KJUR.asn1.x509.AttributeTypeAndValue.superclass.constructor.call(this);
    var typeObj = null;
    var valueObj = null;
    var defaultDSType = "utf8";

    this.setByString = function(attrTypeAndValueStr) {
        if (attrTypeAndValueStr.match(/^([^=]+)=(.+)$/)) {
            this.setByAttrTypeAndValueStr(RegExp.$1, RegExp.$2);
        } else {
            throw "malformed attrTypeAndValueStr: " + attrTypeAndValueStr;
        }
    };

    this.setByAttrTypeAndValueStr = function(shortAttrType, valueStr) {
        this.typeObj = KJUR.asn1.x509.OID.atype2obj(shortAttrType);
        var dsType = defaultDSType;
        if (shortAttrType == "C") dsType = "prn";
        this.valueObj = this.getValueObj(dsType, valueStr);
    };

    this.getValueObj = function(dsType, valueStr) {
        if (dsType == "utf8")   return new KJUR.asn1.DERUTF8String({"str": valueStr});
        if (dsType == "prn")    return new KJUR.asn1.DERPrintableString({"str": valueStr});
        if (dsType == "tel")    return new KJUR.asn1.DERTeletexString({"str": valueStr});
        if (dsType == "ia5")    return new KJUR.asn1.DERIA5String({"str": valueStr});
        throw "unsupported directory string type: type=" + dsType + " value=" + valueStr;
    };

    this.getEncodedHex = function() {
        var o = new KJUR.asn1.DERSequence({"array": [this.typeObj, this.valueObj]});
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };

    if (typeof params != "undefined") {
        if (typeof params['str'] != "undefined") {
            this.setByString(params['str']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AttributeTypeAndValue, KJUR.asn1.ASN1Object);

// === END   X500Name Related =================================================

// === BEGIN Other ASN1 structure class  ======================================

/**
 * SubjectPublicKeyInfo ASN.1 structure class
 * @name KJUR.asn1.x509.SubjectPublicKeyInfo
 * @class SubjectPublicKeyInfo ASN.1 structure class
 * @param {Object} params parameter for subject public key
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>{@link RSAKey} object</li>
 * <li>{@link KJUR.crypto.ECDSA} object</li>
 * <li>{@link KJUR.crypto.DSA} object</li>
 * <li>(DEPRECATED)rsakey - specify {@link RSAKey} object of subject public key</li>
 * <li>(DEPRECATED)rsapem - specify a string of PEM public key of RSA key</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: DSA/ECDSA key object is also supported since asn1x509 1.0.6.<br/>
 * <h4>EXAMPLE</h4>
 * @example
 * var spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(RSAKey_object);
 * var spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(KJURcryptoECDSA_object);
 * var spki = new KJUR.asn1.x509.SubjectPublicKeyInfo(KJURcryptoDSA_object);
 */
KJUR.asn1.x509.SubjectPublicKeyInfo = function(params) {
    KJUR.asn1.x509.SubjectPublicKeyInfo.superclass.constructor.call(this);
    var asn1AlgId = null;
    var asn1SubjPKey = null;
    var rsaKey = null;

    /**
     * (DEPRECATED) set RSAKey object as subject public key
     * @name setRSAKey
     * @memberOf KJUR.asn1.x509.SubjectPublicKeyInfo
     * @function
     * @param {RSAKey} rsaKey {@link RSAKey} object for RSA public key
     * @description
     * @deprecated
     * @example
     * spki.setRSAKey(rsaKey);
     */
    this.setRSAKey = function(rsaKey) {
        if (! RSAKey.prototype.isPrototypeOf(rsaKey))
            throw "argument is not RSAKey instance";
        this.rsaKey = rsaKey;
        var asn1RsaN = new KJUR.asn1.DERInteger({'bigint': rsaKey.n});
        var asn1RsaE = new KJUR.asn1.DERInteger({'int': rsaKey.e});
        var asn1RsaPub = new KJUR.asn1.DERSequence({'array': [asn1RsaN, asn1RsaE]});
        var rsaKeyHex = asn1RsaPub.getEncodedHex();
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({'name':'rsaEncryption'});
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({'hex':'00'+rsaKeyHex});
    };

    /**
     * (DEPRECATED) set a PEM formatted RSA public key string as RSA public key
     * @name setRSAPEM
     * @memberOf KJUR.asn1.x509.SubjectPublicKeyInfo
     * @function
     * @param {String} rsaPubPEM PEM formatted RSA public key string
     * @deprecated
     * @description
     * @example
     * spki.setRSAPEM(rsaPubPEM);
     */
    this.setRSAPEM = function(rsaPubPEM) {
        if (rsaPubPEM.match(/-----BEGIN PUBLIC KEY-----/)) {
            var s = rsaPubPEM;
            s = s.replace(/^-----[^-]+-----/, '');
            s = s.replace(/-----[^-]+-----\s*$/, '');
            var rsaB64 = s.replace(/\s+/g, '');
            var rsaWA = CryptoJS.enc.Base64.parse(rsaB64);
            var rsaP8Hex = CryptoJS.enc.Hex.stringify(rsaWA);
            var a = _rsapem_getHexValueArrayOfChildrenFromHex(rsaP8Hex);
            var hBitStrVal = a[1];
            var rsaHex = hBitStrVal.substr(2);
            var a3 = _rsapem_getHexValueArrayOfChildrenFromHex(rsaHex);
            var rsaKey = new RSAKey();
            rsaKey.setPublic(a3[0], a3[1]);
            this.setRSAKey(rsaKey);
        } else {
            throw "key not supported";
        }
    };

    /*
     * @since asn1x509 1.0.7
     */
    this.getASN1Object = function() {
        if (this.asn1AlgId == null || this.asn1SubjPKey == null)
            throw "algId and/or subjPubKey not set";
        var o = new KJUR.asn1.DERSequence({'array':
                                           [this.asn1AlgId, this.asn1SubjPKey]});
        return o;
    };

    this.getEncodedHex = function() {
        var o = this.getASN1Object();
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

    this._setRSAKey = function(key) {
        var asn1RsaPub = KJUR.asn1.ASN1Util.newObject({
            'seq': [{'int': {'bigint': key.n}}, {'int': {'int': key.e}}]
        });
        var rsaKeyHex = asn1RsaPub.getEncodedHex();
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({'name':'rsaEncryption'});
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({'hex':'00'+rsaKeyHex});
    };

    this._setEC = function(key) {
        var asn1Params = new KJUR.asn1.DERObjectIdentifier({'name': key.curveName});
        this.asn1AlgId = 
            new KJUR.asn1.x509.AlgorithmIdentifier({'name': 'ecPublicKey',
                                                    'asn1params': asn1Params});
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({'hex': '00' + key.pubKeyHex});
    };

    this._setDSA = function(key) {
        var asn1Params = new KJUR.asn1.ASN1Util.newObject({
            'seq': [{'int': {'bigint': key.p}},
                    {'int': {'bigint': key.q}},
                    {'int': {'bigint': key.g}}]
        });
        this.asn1AlgId = 
            new KJUR.asn1.x509.AlgorithmIdentifier({'name': 'dsa',
                                                    'asn1params': asn1Params});
        var pubInt = new KJUR.asn1.DERInteger({'bigint': key.y});
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({'hex': '00' + pubInt.getEncodedHex()});
    };

    if (typeof params != "undefined") {
        if (typeof RSAKey != 'undefined' && params instanceof RSAKey) {
            this._setRSAKey(params);
        } else if (typeof KJUR.crypto.ECDSA != 'undefined' &&
                   params instanceof KJUR.crypto.ECDSA) {
            this._setEC(params);
        } else if (typeof KJUR.crypto.DSA != 'undefined' &&
                   params instanceof KJUR.crypto.DSA) {
            this._setDSA(params);
        } else if (typeof params['rsakey'] != "undefined") {
            this.setRSAKey(params['rsakey']);
        } else if (typeof params['rsapem'] != "undefined") {
            this.setRSAPEM(params['rsapem']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.SubjectPublicKeyInfo, KJUR.asn1.ASN1Object);

/**
 * Time ASN.1 structure class
 * @name KJUR.asn1.x509.Time
 * @class Time ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'str': '130508235959Z'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * <br/>
 * <h4>EXAMPLES</h4>
 * @example
 * var t1 = new KJUR.asn1.x509.Time{'str': '130508235959Z'} // UTCTime by default
 * var t2 = new KJUR.asn1.x509.Time{'type': 'gen',  'str': '20130508235959Z'} // GeneralizedTime
 */
KJUR.asn1.x509.Time = function(params) {
    KJUR.asn1.x509.Time.superclass.constructor.call(this);
    var type = null;
    var timeParams = null;

    this.setTimeParams = function(timeParams) {
        this.timeParams = timeParams;
    }

    this.getEncodedHex = function() {
        var o = null;

        if (this.timeParams != null) {
            if (this.type == "utc") {
                o = new KJUR.asn1.DERUTCTime(this.timeParams);
            } else {
                o = new KJUR.asn1.DERGeneralizedTime(this.timeParams);
            }
        } else {
            if (this.type == "utc") {
                o = new KJUR.asn1.DERUTCTime();
            } else {
                o = new KJUR.asn1.DERGeneralizedTime();
            }
        }
        this.TLV = o.getEncodedHex();
        return this.TLV;
    };
    
    this.type = "utc";
    if (typeof params != "undefined") {
        if (typeof params.type != "undefined") {
            this.type = params.type;
        } else {
            if (typeof params.str != "undefined") {
                if (params.str.match(/^[0-9]{12}Z$/)) this.type = "utc";
                if (params.str.match(/^[0-9]{14}Z$/)) this.type = "gen";
            }
        }
        this.timeParams = params;
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Time, KJUR.asn1.ASN1Object);

/**
 * AlgorithmIdentifier ASN.1 structure class
 * @name KJUR.asn1.x509.AlgorithmIdentifier
 * @class AlgorithmIdentifier ASN.1 structure class
 * @param {Array} params associative array of parameters (ex. {'name': 'SHA1withRSA'})
 * @extends KJUR.asn1.ASN1Object
 * @description
 * @example
 */
KJUR.asn1.x509.AlgorithmIdentifier = function(params) {
    KJUR.asn1.x509.AlgorithmIdentifier.superclass.constructor.call(this);
    var nameAlg = null;
    var asn1Alg = null;
    var asn1Params = null;
    var paramEmpty = false;

    this.getEncodedHex = function() {
        if (this.nameAlg == null && this.asn1Alg == null) {
            throw "algorithm not specified";
        }
        if (this.nameAlg != null && this.asn1Alg == null) {
            this.asn1Alg = KJUR.asn1.x509.OID.name2obj(this.nameAlg);
        }
        var a = [this.asn1Alg];
        if (! this.paramEmpty) a.push(this.asn1Params);
        var o = new KJUR.asn1.DERSequence({'array': a});
        this.hTLV = o.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params['name'] != "undefined") {
            this.nameAlg = params['name'];
        }
        if (typeof params['asn1params'] != "undefined") {
            this.asn1Params = params['asn1params'];
        }
        if (typeof params['paramempty'] != "undefined") {
            this.paramEmpty = params['paramempty'];
        }
    }
    if (this.asn1Params == null) {
        this.asn1Params = new KJUR.asn1.DERNull();
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AlgorithmIdentifier, KJUR.asn1.ASN1Object);

/**
 * GeneralName ASN.1 structure class
 * @name KJUR.asn1.x509.GeneralName
 * @class GeneralName ASN.1 structure class
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>rfc822 - rfc822Name[1] (ex. user1@foo.com)</li>
 * <li>dns - dNSName[2] (ex. foo.com)</li>
 * <li>uri - uniformResourceIdentifier[6] (ex. http://foo.com/)</li>
 * <li>certissuer - directoryName[4] (PEM or hex string of cert)</li>
 * <li>certsubj - directoryName[4] (PEM or hex string of cert)</li>
 * </ul>
 * NOTE1: certissuer and certsubj is supported since asn1x509 1.0.10.
 *
 * Here is definition of the ASN.1 syntax:
 * <pre>
 * -- NOTE: under the CHOICE, it will always be explicit.
 * GeneralName ::= CHOICE {
 *         otherName                       [0]     OtherName,
 *         rfc822Name                      [1]     IA5String,
 *         dNSName                         [2]     IA5String,
 *         x400Address                     [3]     ORAddress,
 *         directoryName                   [4]     Name,
 *         ediPartyName                    [5]     EDIPartyName,
 *         uniformResourceIdentifier       [6]     IA5String,
 *         iPAddress                       [7]     OCTET STRING,
 *         registeredID                    [8]     OBJECT IDENTIFIER } 
 * </pre>
 *
 * 
 *
 * @example
 * gn = new KJUR.asn1.x509.GeneralName({rfc822:      'test@aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({dns:         'aaa.com'});
 * gn = new KJUR.asn1.x509.GeneralName({uri:         'http://aaa.com/'});
 * gn = new KJUR.asn1.x509.GeneralName({certissuer:  certPEM});
 * gn = new KJUR.asn1.x509.GeneralName({certsubj:    certPEM});
 */
KJUR.asn1.x509.GeneralName = function(params) {
    KJUR.asn1.x509.GeneralName.superclass.constructor.call(this);
    var asn1Obj = null;
    var type = null;
    var pTag = {rfc822: '81', dns: '82', dn: 'a4',  uri: '86'};
    this.explicit = false;

    this.setByParam = function(params) {
        var str = null;
        var v = null;

		if (typeof params == "undefined") return;
		
        if (typeof params.rfc822 != "undefined") {
            this.type = 'rfc822';
            v = new KJUR.asn1.DERIA5String({'str': params[this.type]});
        }
        if (typeof params.dns != "undefined") {
            this.type = 'dns';
            v = new KJUR.asn1.DERIA5String({'str': params[this.type]});
        }
        if (typeof params.uri != "undefined") {
            this.type = 'uri';
            v = new KJUR.asn1.DERIA5String({'str': params[this.type]});
        }
		if (typeof params.certissuer != "undefined") {
			this.type = 'dn';
			this.explicit = true;
			var certStr = params.certissuer;
			var certHex = null;
			if (certStr.match(/^[0-9A-Fa-f]+$/)) {
				certHex == certStr;
            }
		    if (certStr.indexOf("-----BEGIN ") != -1) {
				certHex = X509.pemToHex(certStr);
			}
		    if (certHex == null) throw "certissuer param not cert";
			var x = new X509();
			x.hex = certHex;
			var dnHex = x.getIssuerHex();
			v = new KJUR.asn1.ASN1Object();
			v.hTLV = dnHex;
		}
		if (typeof params.certsubj != "undefined") {
			this.type = 'dn';
			this.explicit = true;
			var certStr = params.certsubj;
			var certHex = null;
			if (certStr.match(/^[0-9A-Fa-f]+$/)) {
				certHex == certStr;
            }
		    if (certStr.indexOf("-----BEGIN ") != -1) {
				certHex = X509.pemToHex(certStr);
			}
		    if (certHex == null) throw "certsubj param not cert";
			var x = new X509();
			x.hex = certHex;
			var dnHex = x.getSubjectHex();
			v = new KJUR.asn1.ASN1Object();
			v.hTLV = dnHex;
		}

        if (this.type == null)
            throw "unsupported type in params=" + params;
        this.asn1Obj = new KJUR.asn1.DERTaggedObject({'explicit': this.explicit,
                                                      'tag': pTag[this.type],
                                                      'obj': v});
    };

    this.getEncodedHex = function() {
        return this.asn1Obj.getEncodedHex();
    }

    if (typeof params != "undefined") {
        this.setByParam(params);
    }

};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralName, KJUR.asn1.ASN1Object);

/**
 * GeneralNames ASN.1 structure class
 * @name KJUR.asn1.x509.GeneralNames
 * @class GeneralNames ASN.1 structure class
 * @description
 * <br/>
 * <h4>EXAMPLE AND ASN.1 SYNTAX</h4>
 * @example
 * var gns = new KJUR.asn1.x509.GeneralNames([{'uri': 'http://aaa.com/'}, {'uri': 'http://bbb.com/'}]); 
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 */
KJUR.asn1.x509.GeneralNames = function(paramsArray) {
    KJUR.asn1.x509.GeneralNames.superclass.constructor.call(this);
    var asn1Array = null;

    /**
     * set a array of {@link KJUR.asn1.x509.GeneralName} parameters
     * @name setByParamArray
     * @memberOf KJUR.asn1.x509.GeneralNames
     * @function
     * @param {Array} paramsArray Array of {@link KJUR.asn1.x509.GeneralNames}
     * @description
     * <br/>
     * <h4>EXAMPLES</h4>
     * @example
     * var gns = new KJUR.asn1.x509.GeneralNames();
     * gns.setByParamArray([{'uri': 'http://aaa.com/'}, {'uri': 'http://bbb.com/'}]);
     */
    this.setByParamArray = function(paramsArray) {
        for (var i = 0; i < paramsArray.length; i++) {
            var o = new KJUR.asn1.x509.GeneralName(paramsArray[i]);
            this.asn1Array.push(o);
        }
    };

    this.getEncodedHex = function() {
        var o = new KJUR.asn1.DERSequence({'array': this.asn1Array});
        return o.getEncodedHex();
    };

    this.asn1Array = new Array();
    if (typeof paramsArray != "undefined") {
        this.setByParamArray(paramsArray);
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralNames, KJUR.asn1.ASN1Object);

/**
 * DistributionPointName ASN.1 structure class
 * @name KJUR.asn1.x509.DistributionPointName
 * @class DistributionPointName ASN.1 structure class
 * @description
 * @example
 */
KJUR.asn1.x509.DistributionPointName = function(gnOrRdn) {
    KJUR.asn1.x509.DistributionPointName.superclass.constructor.call(this);
    var asn1Obj = null;
    var type = null;
    var tag = null;
    var asn1V = null;

    this.getEncodedHex = function() {
        if (this.type != "full")
            throw "currently type shall be 'full': " + this.type;
        this.asn1Obj = new KJUR.asn1.DERTaggedObject({'explicit': false,
                                                      'tag': this.tag,
                                                      'obj': this.asn1V});
        this.hTLV = this.asn1Obj.getEncodedHex();
        return this.hTLV;
    };

    if (typeof gnOrRdn != "undefined") {
        if (KJUR.asn1.x509.GeneralNames.prototype.isPrototypeOf(gnOrRdn)) {
            this.type = "full";
            this.tag = "a0";
            this.asn1V = gnOrRdn;
        } else {
            throw "This class supports GeneralNames only as argument";
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPointName, KJUR.asn1.ASN1Object);

/**
 * DistributionPoint ASN.1 structure class
 * @name KJUR.asn1.x509.DistributionPoint
 * @class DistributionPoint ASN.1 structure class
 * @description
 * @example
 */
KJUR.asn1.x509.DistributionPoint = function(params) {
    KJUR.asn1.x509.DistributionPoint.superclass.constructor.call(this);
    var asn1DP = null;

    this.getEncodedHex = function() {
        var seq = new KJUR.asn1.DERSequence();
        if (this.asn1DP != null) {
            var o1 = new KJUR.asn1.DERTaggedObject({'explicit': true,
                                                    'tag': 'a0',
                                                    'obj': this.asn1DP});
            seq.appendASN1Object(o1);
        }
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (typeof params != "undefined") {
        if (typeof params['dpobj'] != "undefined") {
            this.asn1DP = params['dpobj'];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPoint, KJUR.asn1.ASN1Object);

/**
 * static object for OID
 * @name KJUR.asn1.x509.OID
 * @class static object for OID
 * @property {Assoc Array} atype2oidList for short attribyte type name and oid (i.e. 'C' and '2.5.4.6')
 * @property {Assoc Array} name2oidList for oid name and oid (i.e. 'keyUsage' and '2.5.29.15')
 * @property {Assoc Array} objCache for caching name and DERObjectIdentifier object 
 * @description
 * <dl>
 * <dt><b>atype2oidList</b>
 * <dd>currently supports 'C', 'O', 'OU', 'ST', 'L' and 'CN' only.
 * <dt><b>name2oidList</b>
 * <dd>currently supports 'SHA1withRSA', 'rsaEncryption' and some extension OIDs
 * </dl>
 * @example
 */
KJUR.asn1.x509.OID = new function(params) {
    this.atype2oidList = {
        'C':    '2.5.4.6',
        'O':    '2.5.4.10',
        'OU':   '2.5.4.11',
        'ST':   '2.5.4.8',
        'L':    '2.5.4.7',
        'CN':   '2.5.4.3',
        'SN':   '2.5.4.4',
        'DN':   '2.5.4.49',
        'DC':   '0.9.2342.19200300.100.1.25',
    };
    this.name2oidList = {
        'sha1':                 '1.3.14.3.2.26',
        'sha256':               '2.16.840.1.101.3.4.2.1',
        'sha384':               '2.16.840.1.101.3.4.2.2',
        'sha512':               '2.16.840.1.101.3.4.2.3',
        'sha224':               '2.16.840.1.101.3.4.2.4',
        'md5':                  '1.2.840.113549.2.5',
        'md2':                  '1.3.14.7.2.2.1',
        'ripemd160':            '1.3.36.3.2.1',

        'MD2withRSA':           '1.2.840.113549.1.1.2',
        'MD4withRSA':           '1.2.840.113549.1.1.3',
        'MD5withRSA':           '1.2.840.113549.1.1.4',
        'SHA1withRSA':          '1.2.840.113549.1.1.5',
        'SHA224withRSA':        '1.2.840.113549.1.1.14',
        'SHA256withRSA':        '1.2.840.113549.1.1.11',
        'SHA384withRSA':        '1.2.840.113549.1.1.12',
        'SHA512withRSA':        '1.2.840.113549.1.1.13',

        'SHA1withECDSA':        '1.2.840.10045.4.1',
        'SHA224withECDSA':      '1.2.840.10045.4.3.1',
        'SHA256withECDSA':      '1.2.840.10045.4.3.2',
        'SHA384withECDSA':      '1.2.840.10045.4.3.3',
        'SHA512withECDSA':      '1.2.840.10045.4.3.4',

        'dsa':                  '1.2.840.10040.4.1',
        'SHA1withDSA':          '1.2.840.10040.4.3',
        'SHA224withDSA':        '2.16.840.1.101.3.4.3.1',
        'SHA256withDSA':        '2.16.840.1.101.3.4.3.2',

        'rsaEncryption':        '1.2.840.113549.1.1.1',

        'countryName':          '2.5.4.6',
        'organization':         '2.5.4.10',
        'organizationalUnit':   '2.5.4.11',
        'stateOrProvinceName':  '2.5.4.8',
        'locality':             '2.5.4.7',
        'commonName':           '2.5.4.3',

        'subjectKeyIdentifier': '2.5.29.14',
        'keyUsage':             '2.5.29.15',
        'subjectAltName':       '2.5.29.17',
        'basicConstraints':     '2.5.29.19',
        'nameConstraints':      '2.5.29.30',
        'cRLDistributionPoints':'2.5.29.31',
        'certificatePolicies':  '2.5.29.32',
        'authorityKeyIdentifier':'2.5.29.35',
        'policyConstraints':    '2.5.29.36',
        'extKeyUsage':          '2.5.29.37',
	'authorityInfoAccess':  '1.3.6.1.5.5.7.1.1',

        'anyExtendedKeyUsage':  '2.5.29.37.0',
        'serverAuth':           '1.3.6.1.5.5.7.3.1',
        'clientAuth':           '1.3.6.1.5.5.7.3.2',
        'codeSigning':          '1.3.6.1.5.5.7.3.3',
        'emailProtection':      '1.3.6.1.5.5.7.3.4',
        'timeStamping':         '1.3.6.1.5.5.7.3.8',
        'ocspSigning':          '1.3.6.1.5.5.7.3.9',

        'ecPublicKey':          '1.2.840.10045.2.1',
        'secp256r1':            '1.2.840.10045.3.1.7',
        'secp256k1':            '1.3.132.0.10',
        'secp384r1':            '1.3.132.0.34',

        'pkcs5PBES2':           '1.2.840.113549.1.5.13',
        'pkcs5PBKDF2':          '1.2.840.113549.1.5.12',

        'des-EDE3-CBC':         '1.2.840.113549.3.7',

        'data':                 '1.2.840.113549.1.7.1', // CMS data
        'signed-data':          '1.2.840.113549.1.7.2', // CMS signed-data
        'enveloped-data':       '1.2.840.113549.1.7.3', // CMS enveloped-data
        'digested-data':        '1.2.840.113549.1.7.5', // CMS digested-data
        'encrypted-data':       '1.2.840.113549.1.7.6', // CMS encrypted-data
        'authenticated-data':   '1.2.840.113549.1.9.16.1.2', // CMS authenticated-data
        'tstinfo':              '1.2.840.113549.1.9.16.1.4', // RFC3161 TSTInfo
    };

    this.objCache = {};

    /**
     * get DERObjectIdentifier by registered OID name
     * @name name2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} name OID
     * @description
     * @example
     * var asn1ObjOID = OID.name2obj('SHA1withRSA');
     */
    this.name2obj = function(name) {
        if (typeof this.objCache[name] != "undefined")
            return this.objCache[name];
        if (typeof this.name2oidList[name] == "undefined")
            throw "Name of ObjectIdentifier not defined: " + name;
        var oid = this.name2oidList[name];
        var obj = new KJUR.asn1.DERObjectIdentifier({'oid': oid});
        this.objCache[name] = obj;
        return obj;
    };

    /**
     * get DERObjectIdentifier by registered attribyte type name such like 'C' or 'CN'
     * @name atype2obj
     * @memberOf KJUR.asn1.x509.OID
     * @function
     * @param {String} atype short attribute type name such like 'C' or 'CN'
     * @description
     * @example
     * var asn1ObjOID = OID.atype2obj('CN');
     */
    this.atype2obj = function(atype) {
        if (typeof this.objCache[atype] != "undefined")
            return this.objCache[atype];
        if (typeof this.atype2oidList[atype] == "undefined")
            throw "AttributeType name undefined: " + atype;
        var oid = this.atype2oidList[atype];
        var obj = new KJUR.asn1.DERObjectIdentifier({'oid': oid});
        this.objCache[atype] = obj;
        return obj;
    };
};

/*
 * convert OID to name
 * @name oid2name
 * @memberOf KJUR.asn1.x509.OID
 * @function
 * @param {String} dot noted Object Identifer string (ex. 1.2.3.4)
 * @return {String} OID name
 * @description
 * This static method converts OID string to its name.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * name = KJUR.asn1.x509.OID.oid2name("1.3.6.1.5.5.7.1.1");
 * // name will be 'authorityInfoAccess'.
 * @since asn1x509 1.0.9
 */
KJUR.asn1.x509.OID.oid2name = function(oid) {
    var list = KJUR.asn1.x509.OID.name2oidList;
    for (var name in list) {
        if (list[name] == oid) return name;
    }
    return '';
};

/*
 * convert name to OID
 * @name name2oid
 * @memberOf KJUR.asn1.x509.OID
 * @function
 * @param {String} OID name
 * @return {String} dot noted Object Identifer string (ex. 1.2.3.4)
 * @description
 * This static method converts from OID name to OID string.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * name = KJUR.asn1.x509.OID.name2oid("authorityInfoAccess");
 * // name will be '1.3.6.1.5.5.7.1.1'.
 * @since asn1x509 1.0.11
 */
KJUR.asn1.x509.OID.name2oid = function(name) {
    var list = KJUR.asn1.x509.OID.name2oidList;
    if (list[name] === undefined) return '';
    return list[name];
};

/**
 * X.509 certificate and CRL utilities class
 * @name KJUR.asn1.x509.X509Util
 * @class X.509 certificate and CRL utilities class
 */
KJUR.asn1.x509.X509Util = new function() {
    /**
     * get PKCS#8 PEM public key string from RSAKey object
     * @name getPKCS8PubKeyPEMfromRSAKey
     * @memberOf KJUR.asn1.x509.X509Util
     * @function
     * @param {RSAKey} rsaKey RSA public key of {@link RSAKey} object
     * @description
     * @example
     * var pem = KJUR.asn1.x509.X509Util.getPKCS8PubKeyPEMfromRSAKey(pubKey);
     */
    this.getPKCS8PubKeyPEMfromRSAKey = function(rsaKey) {
        var pem = null;
        var hN = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(rsaKey.n);
        var hE = KJUR.asn1.ASN1Util.integerToByteHex(rsaKey.e);
        var iN = new KJUR.asn1.DERInteger({hex: hN});
        var iE = new KJUR.asn1.DERInteger({hex: hE});
        var asn1PubKey = new KJUR.asn1.DERSequence({array: [iN, iE]});
        var hPubKey = asn1PubKey.getEncodedHex();
        var o1 = new KJUR.asn1.x509.AlgorithmIdentifier({name: 'rsaEncryption'});
        var o2 = new KJUR.asn1.DERBitString({hex: '00' + hPubKey});
        var seq = new KJUR.asn1.DERSequence({array: [o1, o2]});
        var hP8 = seq.getEncodedHex();
        var pem = KJUR.asn1.ASN1Util.getPEMStringFromHex(hP8, "PUBLIC KEY");
        return pem;
    };
};
/**
 * issue a certificate in PEM format
 * @name newCertPEM
 * @memberOf KJUR.asn1.x509.X509Util
 * @function
 * @param {Array} param parameter to issue a certificate
 * @since asn1x509 1.0.6
 * @description
 * This method can issue a certificate by a simple
 * JSON object.
 * Signature value will be provided by signing with 
 * private key using 'cakey' parameter or 
 * hexa decimal signature value by 'sighex' parameter.
 *
 * NOTE: When using DSA or ECDSA CA signing key,
 * use 'paramempty' in 'sigalg' to ommit parameter field
 * of AlgorithmIdentifer. In case of RSA, parameter
 * NULL will be specified by default.
 *
 * @example
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM(
 * { serial: {int: 4},
 *   sigalg: {name: 'SHA1withECDSA', paramempty: true},
 *   issuer: {str: '/C=US/O=a'},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {str: '/C=US/O=b'},
 *   sbjpubkey: pubKeyPEM,
 *   ext: [
 *     {basicConstraints: {cA: true, critical: true}},
 *     {keyUsage: {bin: '11'}},
 *   ],
 *   cakey: [prvkey, pass]}
 * );
 * // -- or --
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM(
 * { serial: {int: 1},
 *   sigalg: {name: 'SHA1withRSA', paramempty: true},
 *   issuer: {str: '/C=US/O=T1'},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {str: '/C=US/O=T1'},
 *   sbjpubkey: pubKeyObj,
 *   sighex: '0102030405..'}
 * );
 * // for the issuer and subject field, another
 * // representation is also available
 * var certPEM = KJUR.asn1.x509.X509Util.newCertPEM(
 * { serial: {int: 1},
 *   sigalg: {name: 'SHA1withRSA', paramempty: true},
 *   issuer: {C: "US", O: "T1"},
 *   notbefore: {'str': '130504235959Z'},
 *   notafter: {'str': '140504235959Z'},
 *   subject: {C: "US", O: "T1", CN: "http://example.com/"},
 *   sbjpubkey: pubKeyObj,
 *   sighex: '0102030405..'}
 * );
 */
KJUR.asn1.x509.X509Util.newCertPEM = function(param) {
    var ns1 = KJUR.asn1.x509;
    var o = new ns1.TBSCertificate();

    if (param.serial !== undefined)
        o.setSerialNumberByParam(param.serial);
    else
        throw "serial number undefined.";

    if (typeof param.sigalg.name == 'string')
        o.setSignatureAlgByParam(param.sigalg);
    else 
        throw "unproper signature algorithm name";

    if (param.issuer !== undefined)
        o.setIssuerByParam(param.issuer);
    else
        throw "issuer name undefined.";
    
    if (param.notbefore !== undefined)
        o.setNotBeforeByParam(param.notbefore);
    else
        throw "notbefore undefined.";

    if (param.notafter !== undefined)
        o.setNotAfterByParam(param.notafter);
    else
        throw "notafter undefined.";

    if (param.subject !== undefined)
        o.setSubjectByParam(param.subject);
    else
        throw "subject name undefined.";

    if (param.sbjpubkey !== undefined)
        o.setSubjectPublicKeyByGetKey(param.sbjpubkey);
    else
        throw "subject public key undefined.";

    if (param.ext !== undefined && param.ext.length !== undefined) {
        for (var i = 0; i < param.ext.length; i++) {
            for (key in param.ext[i]) {
                o.appendExtensionByName(key, param.ext[i][key]);
            }
        }
    }

    // set signature
    if (param.cakey === undefined && param.sighex === undefined)
        throw "param cakey and sighex undefined.";

    var caKey = null;
    var cert = null;

    if (param.cakey) {
        caKey = KEYUTIL.getKey.apply(null, param.cakey);
        cert = new ns1.Certificate({'tbscertobj': o, 'prvkeyobj': caKey});
        cert.sign();
    }

    if (param.sighex) {
        cert = new ns1.Certificate({'tbscertobj': o});
        cert.setSignatureHex(param.sighex);
    }

    return cert.getPEMString();
};

/*
  org.bouncycastle.asn1.x500
  AttributeTypeAndValue
  DirectoryString
  RDN
  X500Name
  X500NameBuilder

  org.bouncycastleasn1.x509
  TBSCertificate
*/
/*! x509-1.1.9.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/* 
 * x509.js - X509 class to read subject public key from certificate.
 *
 * Copyright (c) 2010-2016 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name x509-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version x509 1.1.9 (2016-May-10)
 * @since jsrsasign 1.x.x
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/*
 * Depends:
 *   base64.js
 *   rsa.js
 *   asn1hex.js
 */

/**
 * hexadecimal X.509 certificate ASN.1 parser class.<br/>
 * @class hexadecimal X.509 certificate ASN.1 parser class
 * @property {RSAKey} subjectPublicKeyRSA Tom Wu's RSAKey object
 * @property {String} subjectPublicKeyRSA_hN hexadecimal string for modulus of RSA public key
 * @property {String} subjectPublicKeyRSA_hE hexadecimal string for public exponent of RSA public key
 * @property {String} hex hexacedimal string for X.509 certificate.
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jsrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @description
 * X509 class provides following functionality:
 * <ul>
 * <li>parse X.509 certificate ASN.1 structure</li>
 * <li>get basic fields, extensions, signature algorithms and signature values</li>
 * <li>read PEM certificate</li>
 * </ul>
 * 
 * <ul>
 * <li><b>TO GET FIELDS</b>
 *   <ul>
 *   <li>serial - {@link X509#getSerialNumberHex}</li>
 *   <li>issuer - {@link X509#getIssuerHex}</li>
 *   <li>issuer - {@link X509#getIssuerString}</li>
 *   <li>notBefore - {@link X509#getNotBefore}</li>
 *   <li>notAfter - {@link X509#getNotAfter}</li>
 *   <li>subject - {@link X509#getSubjectHex}</li>
 *   <li>subject - {@link X509#getSubjectString}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getSubjectPublicKeyPosFromCertHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getSubjectPublicKeyInfoPosFromCertHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getPublicKeyFromCertPEM}</li>
 *   <li>signature algorithm - {@link X509.getSignatureAlgorithmName}</li>
 *   <li>signature value - {@link X509.getSignatureValueHex}</li>
 *   </ul>
 * </li>
 * <li><b>TO GET EXTENSIONS</b>
 *   <ul>
 *   <li>basicConstraints - {@link X509.getExtBasicConstraints}</li>
 *   <li>keyUsage - {@link X509.getExtKeyUsageBin}</li>
 *   <li>keyUsage - {@link X509.getExtKeyUsageString}</li>
 *   <li>subjectKeyIdentifier - {@link X509.getExtSubjectKeyIdentifier}</li>
 *   <li>authorityKeyIdentifier - {@link X509.getExtAuthorityKeyIdentifier}</li>
 *   <li>extKeyUsage - {@link X509.getExtExtKeyUsageName}</li>
 *   <li>subjectAltName - {@link X509.getExtSubjectAltName}</li>
 *   <li>cRLDistributionPoints - {@link X509.getExtCRLDistributionPointsURI}</li>
 *   <li>authorityInfoAccess - {@link X509.getExtAIAInfo}</li>
 *   </ul>
 * </li>
 * <li><b>UTILITIES</b>
 *   <ul>
 *   <li>reading PEM certificate - {@link X509#readCertPEM}</li>
 *   <li>get all certificate information - {@link X509#getInfo}</li>
 *   <li>get Base64 from PEM certificate - {@link X509.pemToBase64}</li>
 *   <li>get hexadecimal string from PEM certificate - {@link X509.pemToHex}</li>
 *   </ul>
 * </li>
 * </ul>
 */
function X509() {
    this.subjectPublicKeyRSA = null;
    this.subjectPublicKeyRSA_hN = null;
    this.subjectPublicKeyRSA_hE = null;
    this.hex = null;

    // ===== get basic fields from hex =====================================

    /**
     * get hexadecimal string of serialNumber field of certificate.<br/>
     * @name getSerialNumberHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecimal string of certificate serial number
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var sn = x.getSerialNumberHex(); // return string like "01ad..."
     */
    this.getSerialNumberHex = function() {
        return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
    };


    /**
     * get signature algorithm name in basic field
     * @name getSignatureAlgorithmField
     * @memberOf X509#
     * @function
     * @return {String} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
     * @since x509 1.1.8
     * @description
     * This method will get a name of signature algorithm field of certificate:
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * algName = x.getSignatureAlgorithmField();
     */
    this.getSignatureAlgorithmField = function() {
	var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 2, 0]);
	var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex);
	var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt);
	return sigAlgName;
    };

    /**
     * get hexadecimal string of issuer field TLV of certificate.<br/>
     * @name getIssuerHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecial string of issuer DN ASN.1
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var issuer = x.getIssuerHex(); // return string like "3013..."
     */
    this.getIssuerHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
    };

    /**
     * get string of issuer field of certificate.<br/>
     * @name getIssuerString
     * @memberOf X509#
     * @function
     * @return {String} issuer DN string
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var issuer = x.getIssuerString(); // return string like "/C=US/O=TEST"
     */
    this.getIssuerString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
    };

    /**
     * get hexadecimal string of subject field of certificate.<br/>
     * @name getSubjectHex
     * @memberOf X509#
     * @function
     * @return {String} hexadecial string of subject DN ASN.1
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var subject = x.getSubjectHex(); // return string like "3013..."
     */
    this.getSubjectHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
    };

    /**
     * get string of subject field of certificate.<br/>
     * @name getSubjectString
     * @memberOf X509#
     * @function
     * @return {String} subject DN string
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var subject = x.getSubjectString(); // return string like "/C=US/O=TEST"
     */
    this.getSubjectString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
    };

    /**
     * get notBefore field string of certificate.<br/>
     * @name getNotBefore
     * @memberOf X509#
     * @function
     * @return {String} not before time value (ex. "151231235959Z")
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var notBefore = x.getNotBefore(); // return string like "151231235959Z"
     */
    this.getNotBefore = function() {
        var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    /**
     * get notAfter field string of certificate.<br/>
     * @name getNotAfter
     * @memberOf X509#
     * @function
     * @return {String} not after time value (ex. "151231235959Z")
     * @example
     * var x = new X509();
     * x.readCertPEM(sCertPEM);
     * var notAfter = x.getNotAfter(); // return string like "151231235959Z"
     */
    this.getNotAfter = function() {
        var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
        s = s.replace(/(..)/g, "%$1");
        s = decodeURIComponent(s);
        return s;
    };

    // ===== read certificate public key ==========================

    // ===== read certificate =====================================
    /**
     * read PEM formatted X.509 certificate from string.<br/>
     * @name readCertPEM
     * @memberOf X509#
     * @function
     * @param {String} sCertPEM string for PEM formatted X.509 certificate
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // read certificate
     */
    this.readCertPEM = function(sCertPEM) {
        var hCert = X509.pemToHex(sCertPEM);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        var rsa = new RSAKey();
        rsa.setPublic(a[0], a[1]);
        this.subjectPublicKeyRSA = rsa;
        this.subjectPublicKeyRSA_hN = a[0];
        this.subjectPublicKeyRSA_hE = a[1];
        this.hex = hCert;
    };

    this.readCertPEMWithoutRSAInit = function(sCertPEM) {
        var hCert = X509.pemToHex(sCertPEM);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
        this.subjectPublicKeyRSA_hN = a[0];
        this.subjectPublicKeyRSA_hE = a[1];
        this.hex = hCert;
    };

    /**
     * get certificate information as string.<br/>
     * @name getInfo
     * @memberOf X509#
     * @function
     * @return {String} certificate information string
     * @since jsrsasign 5.0.10 x509 1.1.8
     * @example
     * x = new X509();
     * x.readCertPEM(certPEM);
     * console.log(x.getInfo());
     * // this shows as following
     * Basic Fields
     *   serial number: 02ac5c266a0b409b8f0b79f2ae462577
     *   signature algorithm: SHA1withRSA
     *   issuer: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   notBefore: 061110000000Z
     *   notAfter: 311110000000Z
     *   subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   subject public key info: 
     *     key algorithm: RSA
     *     n=c6cce573e6fbd4bb...
     *     e=10001
     * X509v3 Extensions:
     *   keyUsage CRITICAL:
     *     digitalSignature,keyCertSign,cRLSign
     *   basicConstraints CRITICAL:
     *     cA=true
     *   subjectKeyIdentifier :
     *     b13ec36903f8bf4701d498261a0802ef63642bc3
     *   authorityKeyIdentifier :
     *     kid=b13ec36903f8bf4701d498261a0802ef63642bc3
     * signature algorithm: SHA1withRSA
     * signature: 1c1a0697dcd79c9f...
     */
    this.getInfo = function() {
	var s = "Basic Fields\n";
        s += "  serial number: " + this.getSerialNumberHex() + "\n";
	s += "  signature algorithm: " + this.getSignatureAlgorithmField() + "\n";
	s += "  issuer: " + this.getIssuerString() + "\n";
	s += "  notBefore: " + this.getNotBefore() + "\n";
	s += "  notAfter: " + this.getNotAfter() + "\n";
	s += "  subject: " + this.getSubjectString() + "\n";
	s += "  subject public key info: " + "\n";

	// subject public key info
	var pSPKI = X509.getSubjectPublicKeyInfoPosFromCertHex(this.hex);
	var hSPKI = ASN1HEX.getHexOfTLV_AtObj(this.hex, pSPKI);
	var keyObj = KEYUTIL.getKey(hSPKI, null, "pkcs8pub");
	//s += "    " + JSON.stringify(keyObj) + "\n";
	if (keyObj instanceof RSAKey) {
	    s += "    key algorithm: RSA\n";
	    s += "    n=" + keyObj.n.toString(16).substr(0, 16) + "...\n";
	    s += "    e=" + keyObj.e.toString(16) + "\n";
	}

        s += "X509v3 Extensions:\n";

	var aExt = X509.getV3ExtInfoListOfCertHex(this.hex);
        for (var i = 0; i < aExt.length; i++) {
	    var info = aExt[i];

	    // show extension name and critical flag
	    var extName = KJUR.asn1.x509.OID.oid2name(info["oid"]);
	    if (extName === '') extName = info["oid"];

	    var critical = '';
	    if (info["critical"] === true) critical = "CRITICAL";

	    s += "  " + extName + " " + critical + ":\n";

	    // show extension value if supported
	    if (extName === "basicConstraints") {
		var bc = X509.getExtBasicConstraints(this.hex);
		if (bc.cA === undefined) {
		    s += "    {}\n";
		} else {
		    s += "    cA=true";
		    if (bc.pathLen !== undefined) 
			s += ", pathLen=" + bc.pathLen;
		    s += "\n";
		}
	    } else if (extName === "keyUsage") {
		s += "    " + X509.getExtKeyUsageString(this.hex) + "\n";
	    } else if (extName === "subjectKeyIdentifier") {
		s += "    " + X509.getExtSubjectKeyIdentifier(this.hex) + "\n";
	    } else if (extName === "authorityKeyIdentifier") {
		var akid = X509.getExtAuthorityKeyIdentifier(this.hex);
		if (akid.kid !== undefined)
		    s += "    kid=" + akid.kid + "\n";
	    } else if (extName === "extKeyUsage") {
		var eku = X509.getExtExtKeyUsageName(this.hex);
		s += "    " + eku.join(", ") + "\n";
	    } else if (extName === "subjectAltName") {
		var san = X509.getExtSubjectAltName(this.hex);
		s += "    " + san.join(", ") + "\n";
	    } else if (extName === "cRLDistributionPoints") {
		var cdp = X509.getExtCRLDistributionPointsURI(this.hex);
		s += "    " + cdp + "\n";
	    } else if (extName === "authorityInfoAccess") {
		var aia = X509.getExtAIAInfo(this.hex);
		if (aia.ocsp !== undefined)
		    s += "    ocsp: " + aia.ocsp.join(",") + "\n";
		if (aia.caissuer !== undefined)
		    s += "    caissuer: " + aia.caissuer.join(",") + "\n";
	    }
        }

	s += "signature algorithm: " + X509.getSignatureAlgorithmName(this.hex) + "\n";
	s += "signature: " + X509.getSignatureValueHex(this.hex).substr(0, 16) + "...\n";
	return s;
    };
};

/**
 * get Base64 string from PEM certificate string
 * @name pemToBase64
 * @memberOf X509
 * @function
 * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return {String} Base64 string of PEM certificate
 * @example
 * b64 = X509.pemToBase64(certPEM);
 */
X509.pemToBase64 = function(sCertPEM) {
    var s = sCertPEM;
    s = s.replace("-----BEGIN CERTIFICATE-----", "");
    s = s.replace("-----END CERTIFICATE-----", "");
    s = s.replace(/[ \n]+/g, "");
    return s;
};

/**
 * get a hexa decimal string from PEM certificate string
 * @name pemToHex
 * @memberOf X509
 * @function
 * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return {String} hexadecimal string of PEM certificate
 * @example
 * hex = X509.pemToHex(certPEM);
 */
X509.pemToHex = function(sCertPEM) {
    var b64Cert = X509.pemToBase64(sCertPEM);
    var hCert = b64tohex(b64Cert);
    return hCert;
};

// NOTE: Without BITSTRING encapsulation.
X509.getSubjectPublicKeyPosFromCertHex = function(hCert) {
    var pInfo = X509.getSubjectPublicKeyInfoPosFromCertHex(hCert);
    if (pInfo == -1) return -1;    
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); 
    if (a.length != 2) return -1;
    var pBitString = a[1];
    if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
    var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);
    
    if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
    return pBitStringV + 2;
};

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
X509.getSubjectPublicKeyInfoPosFromCertHex = function(hCert) {
    var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); 
    if (a.length < 1) return -1;
    if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
        if (a.length < 6) return -1;
        return a[6];
    } else {
        if (a.length < 5) return -1;
        return a[5];
    }
};

X509.getPublicKeyHexArrayFromCertHex = function(hCert) {
    var p = X509.getSubjectPublicKeyPosFromCertHex(hCert);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); 
    if (a.length != 2) return [];
    var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]);
    if (hN != null && hE != null) {
        return [hN, hE];
    } else {
        return [];
    }
};

X509.getHexTbsCertificateFromCert = function(hCert) {
    var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
    return pTbsCert;
};

X509.getPublicKeyHexArrayFromCertPEM = function(sCertPEM) {
    var hCert = X509.pemToHex(sCertPEM);
    var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
    return a;
};

X509.hex2dn = function(hDN) {
    var s = "";
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hDN, 0);
    for (var i = 0; i < a.length; i++) {
        var hRDN = ASN1HEX.getHexOfTLV_AtObj(hDN, a[i]);
        s = s + "/" + X509.hex2rdn(hRDN);
    }
    return s;
};

X509.hex2rdn = function(hRDN) {
    var hType = ASN1HEX.getDecendantHexTLVByNthList(hRDN, 0, [0, 0]);
    var hValue = ASN1HEX.getDecendantHexVByNthList(hRDN, 0, [0, 1]);
    var type = "";
    try { type = X509.DN_ATTRHEX[hType]; } catch (ex) { type = hType; }
    hValue = hValue.replace(/(..)/g, "%$1");
    var value = decodeURIComponent(hValue);
    return type + "=" + value;
};

X509.DN_ATTRHEX = {
    "0603550406": "C",
    "060355040a": "O",
    "060355040b": "OU",
    "0603550403": "CN",
    "0603550405": "SN",
    "0603550408": "ST",
    "0603550407": "L",
    "0603550409": "streetAddress",
    "060355040f": "businessCategory",
    "0603550411": "postalCode",
    "060b2b0601040182373c020102": "jurisdictionOfIncorporationSP",
    "060b2b0601040182373c020103": "jurisdictionOfIncorporationC",
};

/**
 * get RSAKey/ECDSA public key object from PEM certificate string
 * @name getPublicKeyFromCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
 * @since x509 1.1.1
 * @description
 * NOTE: DSA is also supported since x509 1.1.2.
 */
X509.getPublicKeyFromCertPEM = function(sCertPEM) {
    var info = X509.getPublicKeyInfoPropOfCertPEM(sCertPEM);

    if (info.algoid == "2a864886f70d010101") { // RSA
        var aRSA = KEYUTIL.parsePublicRawRSAKeyHex(info.keyhex);
        var key = new RSAKey();
        key.setPublic(aRSA.n, aRSA.e);
        return key;
    } else if (info.algoid == "2a8648ce3d0201") { // ECC
        var curveName = KJUR.crypto.OID.oidhex2name[info.algparam];
        var key = new KJUR.crypto.ECDSA({'curve': curveName, 'info': info.keyhex});
        key.setPublicKeyHex(info.keyhex);
        return key;
    } else if (info.algoid == "2a8648ce380401") { // DSA 1.2.840.10040.4.1
        var p = ASN1HEX.getVbyList(info.algparam, 0, [0], "02");
        var q = ASN1HEX.getVbyList(info.algparam, 0, [1], "02");
        var g = ASN1HEX.getVbyList(info.algparam, 0, [2], "02");
        var y = ASN1HEX.getHexOfV_AtObj(info.keyhex, 0);
        y = y.substr(2);
        var key = new KJUR.crypto.DSA();
        key.setPublic(new BigInteger(p, 16),
                      new BigInteger(q, 16),
                      new BigInteger(g, 16),
                      new BigInteger(y, 16));
        return key;
    } else {
        throw "unsupported key";
    }
};

/**
 * get public key information from PEM certificate
 * @name getPublicKeyInfoPropOfCertPEM
 * @memberOf X509
 * @function
 * @param {String} sCertPEM string of PEM formatted certificate
 * @return {Hash} hash of information for public key
 * @since x509 1.1.1
 * @description
 * Resulted associative array has following properties:<br/>
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
 * <li>keyhex - hexadecimal string of key in the certificate</li>
 * </ul>
 * NOTE: X509v1 certificate is also supported since x509.js 1.1.9.
 */
X509.getPublicKeyInfoPropOfCertPEM = function(sCertPEM) {
    var result = {};
    result.algparam = null;
    var hCert = X509.pemToHex(sCertPEM);

    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. subjectPublicKeyInfo
    var idx_spi = 6; // subjectPublicKeyInfo index in tbsCert for v3 cert
    if (hCert.substr(a2[0], 2) !== "a0") idx_spi = 5;

    if (a2.length < idx_spi + 1)
        throw "malformed X.509 certificate PEM (code:003)"; // no subjPubKeyInfo

    var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[idx_spi]); 

    if (a3.length != 2)
        throw "malformed X.509 certificate PEM (code:004)"; // not AlgId and PubKey

    // 4. AlgId
    var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); 

    if (a4.length != 2)
        throw "malformed X.509 certificate PEM (code:005)"; // not 2 item in AlgId

    result.algoid = ASN1HEX.getHexOfV_AtObj(hCert, a4[0]);

    if (hCert.substr(a4[1], 2) == "06") { // EC
        result.algparam = ASN1HEX.getHexOfV_AtObj(hCert, a4[1]);
    } else if (hCert.substr(a4[1], 2) == "30") { // DSA
        result.algparam = ASN1HEX.getHexOfTLV_AtObj(hCert, a4[1]);
    }

    // 5. Public Key Hex
    if (hCert.substr(a3[1], 2) != "03")
        throw "malformed X.509 certificate PEM (code:006)"; // not bitstring

    var unusedBitAndKeyHex = ASN1HEX.getHexOfV_AtObj(hCert, a3[1]);
    result.keyhex = unusedBitAndKeyHex.substr(2);

    return result;
};

/**
 * get position of subjectPublicKeyInfo field from HEX certificate
 * @name getPublicKeyInfoPosOfCertHEX
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of certificate
 * @return {Integer} position in hexadecimal string
 * @since x509 1.1.4
 * @description
 * get position for SubjectPublicKeyInfo field in the hexadecimal string of
 * certificate.
 */
X509.getPublicKeyInfoPosOfCertHEX = function(hCert) {
    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. subjectPublicKeyInfo
    if (a2.length < 7)
        throw "malformed X.509 certificate PEM (code:003)"; // no subjPubKeyInfo
    
    return a2[6];
};

/**
 * get array of X.509 V3 extension value information in hex string of certificate
 * @name getV3ExtInfoListOfCertHex
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Array} array of result object by {@link X509.getV3ExtInfoListOfCertHex}
 * @since x509 1.1.5
 * @description
 * This method will get all extension information of a X.509 certificate.
 * Items of resulting array has following properties:
 * <ul>
 * <li>posTLV - index of ASN.1 TLV for the extension. same as 'pos' argument.</li>
 * <li>oid - dot noted string of extension oid (ex. 2.5.29.14)</li>
 * <li>critical - critical flag value for this extension</li>
 * <li>posV - index of ASN.1 TLV for the extension value.
 * This is a position of a content of ENCAPSULATED OCTET STRING.</li>
 * </ul>
 * @example
 * hCert = X509.pemToHex(certGithubPEM);
 * a = X509.getV3ExtInfoListOfCertHex(hCert);
 * // Then a will be an array of like following:
 * [{posTLV: 1952, oid: "2.5.29.35", critical: false, posV: 1968},
 *  {posTLV: 1974, oid: "2.5.29.19", critical: true, posV: 1986}, ...]
 */
X509.getV3ExtInfoListOfCertHex = function(hCert) {
    // 1. Certificate ASN.1
    var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); 
    if (a1.length != 3)
        throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

    // 2. tbsCertificate
    if (hCert.substr(a1[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq 

    var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); 

    // 3. v3Extension EXPLICIT Tag [3]
    // ver, seri, alg, iss, validity, subj, spki, (iui,) (sui,) ext
    if (a2.length < 8)
        throw "malformed X.509 certificate PEM (code:003)"; // tbsCert num field too short

    if (hCert.substr(a2[7], 2) != "a3")
        throw "malformed X.509 certificate PEM (code:004)"; // not [3] tag

    var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[7]);
    if (a3.length != 1)
        throw "malformed X.509 certificate PEM (code:005)"; // [3]tag numChild!=1

    // 4. v3Extension SEQUENCE
    if (hCert.substr(a3[0], 2) != "30")
        throw "malformed X.509 certificate PEM (code:006)"; // not SEQ

    var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]);

    // 5. v3Extension item position
    var numExt = a4.length;
    var aInfo = new Array(numExt);
    for (var i = 0; i < numExt; i++) {
	aInfo[i] = X509.getV3ExtItemInfo_AtObj(hCert, a4[i]);
    }
    return aInfo;
};

/**
 * get X.509 V3 extension value information at the specified position
 * @name getV3ExtItemInfo_AtObj
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {Integer} pos index of hexadecimal string for the extension
 * @return {Object} properties for the extension
 * @since x509 1.1.5
 * @description
 * This method will get some information of a X.509 V extension 
 * which is referred by an index of hexadecimal string of X.509 
 * certificate. 
 * Resulting object has following properties:
 * <ul>
 * <li>posTLV - index of ASN.1 TLV for the extension. same as 'pos' argument.</li>
 * <li>oid - dot noted string of extension oid (ex. 2.5.29.14)</li>
 * <li>critical - critical flag value for this extension</li>
 * <li>posV - index of ASN.1 TLV for the extension value.
 * This is a position of a content of ENCAPSULATED OCTET STRING.</li>
 * </ul>
 * This method is used by {@link X509.getV3ExtInfoListOfCertHex} internally.
 */
X509.getV3ExtItemInfo_AtObj = function(hCert, pos) {
    var info = {};

    // posTLV - extension TLV
    info.posTLV = pos;

    var a  = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos);
    if (a.length != 2 && a.length != 3)
        throw "malformed X.509v3 Ext (code:001)"; // oid,(critical,)val

    // oid - extension OID
    if (hCert.substr(a[0], 2) != "06")
        throw "malformed X.509v3 Ext (code:002)"; // not OID "06"
    var valueHex = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
    info.oid = ASN1HEX.hextooidstr(valueHex); 

    // critical - extension critical flag
    info.critical = false; // critical false by default
    if (a.length == 3) info.critical = true;

    // posV - content TLV position of encapsulated
    //        octet string of V3 extension value.
    var posExtV = a[a.length - 1];
    if (hCert.substr(posExtV, 2) != "04")
        throw "malformed X.509v3 Ext (code:003)"; // not EncapOctet "04"
    info.posV = ASN1HEX.getStartPosOfV_AtObj(hCert, posExtV);
    
    return info;
};

/**
 * get X.509 V3 extension value ASN.1 TLV for specified oid or name
 * @name getHexOfTLV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {String} hexadecimal string of extension ASN.1 TLV
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 TLV
 * which is specifyed by extension name or oid. 
 * If there is no such extension in the certificate, it returns null.
 * @example
 * hExtValue = X509.getHexOfTLV_V3ExtValue(hCert, "keyUsage");
 * // hExtValue will be such like '030205a0'.
 */
X509.getHexOfTLV_V3ExtValue = function(hCert, oidOrName) {
    var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName);
    if (pos == -1) return null;
    return ASN1HEX.getHexOfTLV_AtObj(hCert, pos);
};

/**
 * get X.509 V3 extension value ASN.1 V for specified oid or name
 * @name getHexOfV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {String} hexadecimal string of extension ASN.1 TLV
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 value
 * which is specifyed by extension name or oid. 
 * If there is no such extension in the certificate, it returns null.
 * Available extension names and oids are defined
 * in the {@link KJUR.asn1.x509.OID} class.
 * @example
 * hExtValue = X509.getHexOfV_V3ExtValue(hCert, "keyUsage");
 * // hExtValue will be such like '05a0'.
 */
X509.getHexOfV_V3ExtValue = function(hCert, oidOrName) {
    var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName);
    if (pos == -1) return null;
    return ASN1HEX.getHexOfV_AtObj(hCert, pos);
};

/**
 * get index in the certificate hexa string for specified oid or name specified extension
 * @name getPosOfTLV_V3ExtValue
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @param {String} oidOrName oid or name for extension (ex. 'keyUsage' or '2.5.29.15')
 * @return {Integer} index in the hexadecimal string of certficate for specified extension
 * @since x509 1.1.6
 * @description
 * This method will get X.509v3 extension value of ASN.1 V(value)
 * which is specifyed by extension name or oid. 
 * If there is no such extension in the certificate,
 * it returns -1.
 * Available extension names and oids are defined
 * in the {@link KJUR.asn1.x509.OID} class.
 * @example
 * idx = X509.getPosOfV_V3ExtValue(hCert, "keyUsage");
 * // The 'idx' will be index in the string for keyUsage value ASN.1 TLV.
 */
X509.getPosOfTLV_V3ExtValue = function(hCert, oidOrName) {
    var oid = oidOrName;
    if (! oidOrName.match(/^[0-9.]+$/)) oid = KJUR.asn1.x509.OID.name2oid(oidOrName);
    if (oid == '') return -1;

    var infoList = X509.getV3ExtInfoListOfCertHex(hCert);
    for (var i = 0; i < infoList.length; i++) {
	var info = infoList[i];
	if (info.oid == oid) return info.posV;
    }
    return -1;
};

/* ======================================================================
 *   Specific V3 Extensions
 * ====================================================================== */

/**
 * get BasicConstraints extension value as object in the certificate
 * @name getExtBasicConstraints
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} associative array which may have "cA" and "pathLen" parameters
 * @since x509 1.1.7
 * @description
 * This method will get basic constraints extension value as object with following paramters.
 * <ul>
 * <li>cA - CA flag whether CA or not</li>
 * <li>pathLen - maximum intermediate certificate length</li>
 * </ul>
 * There are use cases for return values:
 * <ul>
 * <li>{cA:true, pathLen:3} - cA flag is true and pathLen is 3</li>
 * <li>{cA:true} - cA flag is true and no pathLen</li>
 * <li>{} - basic constraints has no value in case of end entity certificate</li>
 * <li>null - there is no basic constraints extension</li>
 * </ul>
 * @example
 * obj = X509.getExtBasicConstraints(hCert);
 */
X509.getExtBasicConstraints = function(hCert) {
    var hBC = X509.getHexOfV_V3ExtValue(hCert, "basicConstraints");
    if (hBC === null) return null;
    if (hBC === '') return {};
    if (hBC === '0101ff') return { "cA": true };
    if (hBC.substr(0, 8) === '0101ff02') {
	var pathLexHex = ASN1HEX.getHexOfV_AtObj(hBC, 6);
	var pathLen = parseInt(pathLexHex, 16);
	return { "cA": true, "pathLen": pathLen };
    }
    throw "unknown error";
};

X509.KEYUSAGE_NAME = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly"
];

/**
 * get KeyUsage extension value as binary string in the certificate
 * @name getExtKeyUsageBin
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} binary string of key usage bits (ex. '101')
 * @since x509 1.1.6
 * @description
 * This method will get key usage extension value
 * as binary string such like '101'.
 * Key usage bits definition is in the RFC 5280.
 * If there is no key usage extension in the certificate,
 * it returns empty string (i.e. '').
 * @example
 * bKeyUsage = X509.getExtKeyUsageBin(hCert);
 * // bKeyUsage will be such like '101'.
 * // 1 - digitalSignature 
 * // 0 - nonRepudiation
 * // 1 - keyEncipherment
 */
X509.getExtKeyUsageBin = function(hCert) {
    var hKeyUsage = X509.getHexOfV_V3ExtValue(hCert, "keyUsage");
    if (hKeyUsage == '') return '';
    if (hKeyUsage.length % 2 != 0 || hKeyUsage.length <= 2)
	throw "malformed key usage value";
    var unusedBits = parseInt(hKeyUsage.substr(0, 2));
    var bKeyUsage = parseInt(hKeyUsage.substr(2), 16).toString(2);
    return bKeyUsage.substr(0, bKeyUsage.length - unusedBits);
};

/**
 * get KeyUsage extension value as names in the certificate
 * @name getExtKeyUsageString
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} comma separated string of key usage
 * @since x509 1.1.6
 * @description
 * This method will get key usage extension value
 * as comma separated string of usage names.
 * If there is no key usage extension in the certificate,
 * it returns empty string (i.e. '').
 * @example
 * sKeyUsage = X509.getExtKeyUsageString(hCert);
 * // sKeyUsage will be such like 'digitalSignature,keyEncipherment'.
 */
X509.getExtKeyUsageString = function(hCert) {
    var bKeyUsage = X509.getExtKeyUsageBin(hCert);
    var a = new Array();
    for (var i = 0; i < bKeyUsage.length; i++) {
	if (bKeyUsage.substr(i, 1) == "1") a.push(X509.KEYUSAGE_NAME[i]);
    }
    return a.join(",");
};

/**
 * get subjectKeyIdentifier value as hexadecimal string in the certificate
 * @name getExtSubjectKeyIdentifier
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} hexadecimal string of subject key identifier or null
 * @since jsrsasign 5.0.10 x509 1.1.8
 * @description
 * This method will get subject key identifier extension value
 * as hexadecimal string.
 * If there is no its extension in the certificate,
 * it returns null.
 * @example
 * skid = X509.getExtSubjectKeyIdentifier(hCert);
 */
X509.getExtSubjectKeyIdentifier = function(hCert) {
    var hSKID = X509.getHexOfV_V3ExtValue(hCert, "subjectKeyIdentifier");
    return hSKID;
};

/**
 * get authorityKeyIdentifier value as JSON object in the certificate
 * @name getExtAuthorityKeyIdentifier
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} JSON object of authority key identifier or null
 * @since jsrsasign 5.0.10 x509 1.1.8
 * @description
 * This method will get authority key identifier extension value
 * as JSON object.
 * If there is no its extension in the certificate,
 * it returns null.
 * <br>
 * NOTE: Currently this method only supports keyIdentifier so that
 * authorityCertIssuer and authorityCertSerialNumber will not
 * be return in the JSON object.
 * @example
 * akid = X509.getExtAuthorityKeyIdentifier(hCert);
 * // returns following JSON object
 * { kid: "1234abcd..." }
 */
X509.getExtAuthorityKeyIdentifier = function(hCert) {
    var result = {};
    var hAKID = X509.getHexOfTLV_V3ExtValue(hCert, "authorityKeyIdentifier");
    if (hAKID === null) return null;

    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hAKID, 0); 
    for (var i = 0; i < a.length; i++) {
	if (hAKID.substr(a[i], 2) === "80")
	    result.kid = ASN1HEX.getHexOfV_AtObj(hAKID, a[i]);
    }
    
    return result;
};

/**
 * get extKeyUsage value as array of name string in the certificate
 * @name getExtExtKeyUsageName
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} array of extended key usage ID name or oid
 * @since jsrsasign 5.0.10 x509 1.1.8
 * @description
 * This method will get extended key usage extension value
 * as array of name or OID string.
 * If there is no its extension in the certificate,
 * it returns null.
 * <br>
 * NOTE: Supported extended key usage ID names are defined in
 * name2oidList parameter in asn1x509.js file.
 * @example
 * eku = X509.getExtExtKeyUsageName(hCert);
 * // returns following array:
 * ["serverAuth", "clientAuth", "0.1.2.3.4.5"]
 */
X509.getExtExtKeyUsageName = function(hCert) {
    var result = new Array();
    var h = X509.getHexOfTLV_V3ExtValue(hCert, "extKeyUsage");
    if (h === null) return null;

    var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); 
    for (var i = 0; i < a.length; i++) {
	var hex = ASN1HEX.getHexOfV_AtObj(h, a[i]);
	var oid = KJUR.asn1.ASN1Util.oidHexToInt(hex);
	var name = KJUR.asn1.x509.OID.oid2name(oid);
	result.push(name);
    }
    
    return result;
};

/**
 * get subjectAltName value as array of string in the certificate
 * @name getExtSubjectAltName
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} array of alt names
 * @since jsrsasign 5.0.10 x509 1.1.8
 * @description
 * This method will get subject alt name extension value
 * as array of name.
 * If there is no its extension in the certificate,
 * it returns null.
 * <br>
 * NOTE: Currently this method supports only dNSName so that
 * other name type such like iPAddress or generalName will not be returned.
 * @example
 * san = X509.getExtSubjectAltName(hCert);
 * // returns following array:
 * ["example.com", "example.org"]
 */
X509.getExtSubjectAltName = function(hCert) {
    var result = new Array();
    var h = X509.getHexOfTLV_V3ExtValue(hCert, "subjectAltName");
    
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); 
    for (var i = 0; i < a.length; i++) {
	if (h.substr(a[i], 2) === "82") {
	    var fqdn = hextoutf8(ASN1HEX.getHexOfV_AtObj(h, a[i]));
	    result.push(fqdn);
	}
    }

    return result;
};

/**
 * get array of string for fullName URIs in cRLDistributionPoints(CDP) in the certificate
 * @name getExtCRLDistributionPointsURI
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} array of fullName URIs of CDP of the certificate
 * @since jsrsasign 5.0.10 x509 1.1.8
 * @description
 * This method will get all fullName URIs of cRLDistributionPoints extension
 * in the certificate as array of URI string.
 * If there is no its extension in the certificate,
 * it returns null.
 * <br>
 * NOTE: Currently this method supports only fullName URI so that
 * other parameters will not be returned.
 * @example
 * cdpuri = X509.getExtCRLDistributionPointsURI(hCert);
 * // returns following array:
 * ["http://example.com/aaa.crl", "http://example.org/aaa.crl"]
 */
X509.getExtCRLDistributionPointsURI = function(hCert) {
    var result = new Array();
    var h = X509.getHexOfTLV_V3ExtValue(hCert, "cRLDistributionPoints");

    var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); 
    for (var i = 0; i < a.length; i++) {
	var hDP = ASN1HEX.getHexOfTLV_AtObj(h, a[i]);

	var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hDP, 0); 
	for (var j = 0; j < a1.length; j++) {
	    if (hDP.substr(a1[j], 2) === "a0") {
		var hDPN = ASN1HEX.getHexOfV_AtObj(hDP, a1[j]);
		if (hDPN.substr(0, 2) === "a0") {
		    var hFullName = ASN1HEX.getHexOfV_AtObj(hDPN, 0);
		    if (hFullName.substr(0, 2) === "86") {
			var hURI = ASN1HEX.getHexOfV_AtObj(hFullName, 0);
			var uri = hextoutf8(hURI);
			result.push(uri);
		    }
		}
	    }
	}
    }

    return result;
};

/**
 * get AuthorityInfoAccess extension value in the certificate as associative array
 * @name getExtAIAInfo
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {Object} associative array of AIA extension properties
 * @since x509 1.1.6
 * @description
 * This method will get authority info access value
 * as associate array which has following properties:
 * <ul>
 * <li>ocsp - array of string for OCSP responder URL</li>
 * <li>caissuer - array of string for caIssuer value (i.e. CA certificates URL)</li>
 * </ul>
 * If there is no key usage extension in the certificate,
 * it returns null;
 * @example
 * oAIA = X509.getExtAIAInfo(hCert);
 * // result will be such like:
 * // oAIA.ocsp = ["http://ocsp.foo.com"];
 * // oAIA.caissuer = ["http://rep.foo.com/aaa.p8m"];
 */
X509.getExtAIAInfo = function(hCert) {
    var result = {};
    result.ocsp = [];
    result.caissuer = [];
    var pos1 = X509.getPosOfTLV_V3ExtValue(hCert, "authorityInfoAccess");
    if (pos1 == -1) return null;
    if (hCert.substr(pos1, 2) != "30") // extnValue SEQUENCE
	throw "malformed AIA Extn Value";
    
    var posAccDescList = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos1);
    for (var i = 0; i < posAccDescList.length; i++) {
	var p = posAccDescList[i];
	var posAccDescChild = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p);
	if (posAccDescChild.length != 2)
	    throw "malformed AccessDescription of AIA Extn";
	var pOID = posAccDescChild[0];
	var pName = posAccDescChild[1];
	if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073001") {
	    if (hCert.substr(pName, 2) == "86") {
		result.ocsp.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName)));
	    }
	}
	if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073002") {
	    if (hCert.substr(pName, 2) == "86") {
		result.caissuer.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName)));
	    }
	}
    }
    return result;
};

/**
 * get signature algorithm name from hexadecimal certificate data
 * @name getSignatureAlgorithmName
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
 * @since x509 1.1.7
 * @description
 * This method will get signature algorithm name of certificate:
 * @example
 * algName = X509.getSignatureAlgorithmName(hCert);
 */
X509.getSignatureAlgorithmName = function(hCert) {
    var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [1, 0]);
    var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex);
    var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt);
    return sigAlgName;
};

/**
 * get signature value in hexadecimal string
 * @name getSignatureValueHex
 * @memberOf X509
 * @function
 * @param {String} hCert hexadecimal string of X.509 certificate binary
 * @return {String} signature value hexadecimal string without BitString unused bits
 * @since x509 1.1.7
 * @description
 * This method will get signature value of certificate:
 * @example
 * sigHex = X509.getSignatureValueHex(hCert);
 */
X509.getSignatureValueHex = function(hCert) {
    var h = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [2]);
    if (h.substr(0, 2) !== "00")
	throw "can't get signature value";
    return h.substr(2);
};

X509.getSerialNumberHex = function(hCert) {
    return ASN1HEX.getDecendantHexVByNthList(hCert, 0, [0, 1]);
};

/*
  X509.prototype.readCertPEM = _x509_readCertPEM;
  X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
  X509.prototype.getSerialNumberHex = _x509_getSerialNumberHex;
  X509.prototype.getIssuerHex = _x509_getIssuerHex;
  X509.prototype.getSubjectHex = _x509_getSubjectHex;
  X509.prototype.getIssuerString = _x509_getIssuerString;
  X509.prototype.getSubjectString = _x509_getSubjectString;
  X509.prototype.getNotBefore = _x509_getNotBefore;
  X509.prototype.getNotAfter = _x509_getNotAfter;
*/
//
// rsa-pem.js - adding function for reading/writing PKCS#1 & PKCS#8 PEM private key
//              and reading/wriring x509 public key to RSAKey class
//
// version: 1.0 (2010-Jun-03)
// version: 1.1 (2012-Feb-21)
// version: 1.2 (2012-Jun-23)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
// Copyright (c) 2012 Adrian Pasternak (["adrian", "pasternak", "@", "gmail", ".", "com"].join(""))
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
//

function _rsapem_extractEncodedData(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey) {
  var a = new Array();
  var v1 = _asnhex_getStartPosOfV_AtObj(hPrivateKey, 0);
  var n1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, v1);
  var e1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, n1);
  var d1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, e1);
  var p1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, d1);
  var q1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, p1);
  var dp1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, q1);
  var dq1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dp1);
  var co1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dq1);
  a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey);
  var v =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var n =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var e =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[2]);
  var d =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[3]);
  var p =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[4]);
  var q =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[5]);
  var dp = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[6]);
  var dq = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[7]);
  var co = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[8]);
  var a = new Array();
  a.push(v, n, e, d, p, q, dp, dq, co);
  return a;
}

function _rsapem_getPosArrayOfChildrenFromPublicKeyHex(hPrivateKey) {
  var a = new Array();
  var header = _asnhex_getStartPosOfV_AtObj(hPrivateKey, 0);
  var keys = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, header);
  a.push(header, keys);
  return a;
}

function _rsapem_getPosArrayOfChildrenFromPrivateKeyHex(hPrivateKey) {
  var a = new Array();
  var integer = _asnhex_getStartPosOfV_AtObj(hPrivateKey, 0);
  var header = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, integer);
  var keys = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, header);
  a.push(integer, header, keys);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromPublicKeyHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromPublicKeyHex(hPrivateKey);
  var headerVal =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var keysVal =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[1]);
  
  var keysSequence = keysVal.substring(2);
  posArray = _rsapem_getPosArrayOfChildrenFromPublicKeyHex(keysSequence);
  var modulus =  _asnhex_getHexOfV_AtObj(keysSequence, posArray[0]);
  var publicExp =  _asnhex_getHexOfV_AtObj(keysSequence, posArray[1]);

  var a = new Array();
  a.push(modulus, publicExp);
  return a;
}


function _rsapem_getHexValueArrayOfChildrenFromPrivateKeyHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromPrivateKeyHex(hPrivateKey);
  var integerVal =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var headerVal =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var keysVal =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[2]);
  
  var keysSequence = keysVal.substring(2);
  return _rsapem_getHexValueArrayOfChildrenFromHex(keysSequence);
}

function _rsapem_readPrivateKeyFromPkcs1PemString(keyPEM) {
  var keyB64 = _rsapem_extractEncodedData(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

function _rsapem_readPrivateKeyFromPkcs8PemString(keyPEM) {
  var keyB64 = _rsapem_extractEncodedData(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromPrivateKeyHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

function _rsapem_readPublicKeyFromX509PemString(keyPEM) {
  var keyB64 = _rsapem_extractEncodedData(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromPublicKeyHex(keyHex);
  this.setPublic(a[0],a[1]);
}

/**
* Pad string with leading zeros, to use even number of bytes.
*/
function _rsapem_padWithZero(numString) {
    if (numString.length % 2 == 1) {
        return "0" + numString;
    }
    return numString;
}

/**
* Encode length in DER format (if length <0x80, then one byte, else first byte is 0x80 + length of length :) + n-bytes of length).
*/
function _rsapem_encodeLength(length) {
    if (length >= parseInt("80", 16)) {
        var realLength = _rsapem_padWithZero(length.toString(16));
        var lengthOfLength = (realLength.length / 2);
        return (parseInt("80", 16) + lengthOfLength).toString(16) + realLength;
    } else {
        return _rsapem_padWithZero(length.toString(16));
    }
}

/**
* Encode number in DER encoding ("02" + length + number).
*/
function _rsapem_derEncodeNumber(number) {
    var numberString = _rsapem_padWithZero(number.toString(16));
    if (numberString[0] > '7') {
    	numberString = "00" + numberString;
    }
    var lenString = _rsapem_encodeLength(numberString.length / 2);
    return "02" + lenString + numberString;
}

/**
* Converts private & public part of given key to ASN1 Hex String.
*/
function _rsapem_privateKeyToPkcs1HexString(rsaKey) {
    var result = _rsapem_derEncodeNumber(0);
    result += _rsapem_derEncodeNumber(rsaKey.n);
    result += _rsapem_derEncodeNumber(rsaKey.e);
    result += _rsapem_derEncodeNumber(rsaKey.d);
    result += _rsapem_derEncodeNumber(rsaKey.p);
    result += _rsapem_derEncodeNumber(rsaKey.q);
    result += _rsapem_derEncodeNumber(rsaKey.dmp1);
    result += _rsapem_derEncodeNumber(rsaKey.dmq1);
    result += _rsapem_derEncodeNumber(rsaKey.coeff);

    var fullLen = _rsapem_encodeLength(result.length / 2);
    return '30' + fullLen + result;
}

/**
* Converts private & public part of given key to PKCS#8 Hex String.
*/
function _rsapem_privateKeyToPkcs8HexString(rsaKey) {
	var zeroInteger = "020100";
    var encodedIdentifier = "06092A864886F70D010101";
    var encodedNull = "0500";
    var headerSequence = "300D" + encodedIdentifier + encodedNull;
    var keySequence = _rsapem_privateKeyToPkcs1HexString(rsaKey);
    
    var keyOctetString = "04" + _rsapem_encodeLength(keySequence.length / 2) + keySequence;
    
    var mainSequence = zeroInteger + headerSequence + keyOctetString;
    return "30" + _rsapem_encodeLength(mainSequence.length / 2) + mainSequence;
}

/**
* Converts public part of given key to ASN1 Hex String.
*/
function _rsapem_publicKeyToX509HexString(rsaKey) {
    var encodedIdentifier = "06092A864886F70D010101";
    var encodedNull = "0500";
    var headerSequence = "300D" + encodedIdentifier + encodedNull;

    var keys = _rsapem_derEncodeNumber(rsaKey.n);
    keys += _rsapem_derEncodeNumber(rsaKey.e);

    var keySequence = "0030" + _rsapem_encodeLength(keys.length / 2) + keys;
    var bitstring = "03" + _rsapem_encodeLength(keySequence.length / 2) + keySequence;

    var mainSequence = headerSequence + bitstring;

    return "30" + _rsapem_encodeLength(mainSequence.length / 2) + mainSequence;
}

/**
* Output private & public part of the key in PKCS#1 PEM format.
*/
function _rsapem_privateKeyToPkcs1PemString() {
    return hex2b64(_rsapem_privateKeyToPkcs1HexString(this));
}

/**
* Output private & public part of the key in PKCS#8 PEM format.
*/
function _rsapem_privateKeyToPkcs8PemString() {
    return hex2b64(_rsapem_privateKeyToPkcs8HexString(this));
}

/**
* Output public part of the key in x509 PKCS#1 PEM format.
*/
function _rsapem_publicKeyToX509PemString() {
    return hex2b64(_rsapem_publicKeyToX509HexString(this));
}

function _rsa_splitKey(key, line) {
    var splitKey = "";
    for (var i = 0; i < key.length; i++) {
        if (i % line == 0 && i != 0 && i != (key.length - 1)) {
            splitKey += "\n";
        }
        splitKey += key[i];
    }

    return splitKey;	
}

RSAKey.prototype.readPrivateKeyFromPkcs1PemString = _rsapem_readPrivateKeyFromPkcs1PemString;
RSAKey.prototype.privateKeyToPkcs1PemString = _rsapem_privateKeyToPkcs1PemString;

RSAKey.prototype.readPrivateKeyFromPkcs8PemString = _rsapem_readPrivateKeyFromPkcs8PemString;
RSAKey.prototype.privateKeyToPkcs8PemString = _rsapem_privateKeyToPkcs8PemString;

RSAKey.prototype.readPublicKeyFromX509PEMString = _rsapem_readPublicKeyFromX509PemString;
RSAKey.prototype.publicKeyToX509PemString = _rsapem_publicKeyToX509PemString;


/*! jws-2.0.3 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jws.js - JSON Web Signature Class
 *
 * version: 2.0.3 (2013 Jul 30)
 *
 * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name jws-2.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 2.0.3 (2013-Jul-30)
 * @since jsjws 1.0
 * @license <a href="http://kjur.github.io/jsjws/license/">MIT License</a>
 */

var hmac, const_time_equal;
if (typeof require === 'function')
{
    var crypto = require('crypto');
    hmac = function (alg, key, data)
    {
        var mac = crypto.createHmac(alg, key);
        mac.update(data);
        return mac.digest('base64');
    };

    const_time_equal = function (s1, s2)
    {
        "use strict";
        return (s1.length === s2.length) &&
               crypto.timingSafeEqual(Buffer.from(s1, 'binary'),
                                      Buffer.from(s2, 'binary'));
    };
}
else
{
    hmac = function (alg, key, data)
    {
        var mac = new KJUR.crypto.Mac({alg: 'hmac' + alg, pass: key});
        mac.updateString(data);
        return hex2b64(mac.doFinal());
    };

    // from https://github.com/goinstant/buffer-equal-constant-time/blob/master/index.js
    const_time_equal = function (s1, s2)
    {
        "use strict";
        if (s1.length !== s2.length)
        {
            return false;
        }
        var i, c = 0;
        for (i = 0; i < s1.length; i += 1)
        {
            /*jslint bitwise: true */
            c |= s1.charCodeAt(i) ^ s2.charCodeAt(i); // XOR
            /*jslint bitwise: false */
        }
        return c === 0;
    };
}
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.jws == "undefined" || !KJUR.jws) KJUR.jws = {};

/**
 * JSON Web Signature(JWS) class.<br/>
 * @class JSON Web Signature(JWS) class
 * @property {Dictionary} parsedJWS This property is set after JWS signature verification. <br/>
 *           Following "parsedJWS_*" properties can be accessed as "parsedJWS.*" because of
 *           JsDoc restriction.
 * @property {String} parsedJWS_headB64U string of Encrypted JWS Header
 * @property {String} parsedJWS_payloadB64U string of Encrypted JWS Payload
 * @property {String} parsedJWS_sigvalB64U string of Encrypted JWS signature value
 * @property {String} parsedJWS_si string of Signature Input
 * @property {String} parsedJWS_sigvalH hexadecimal string of JWS signature value
 * @property {String} parsedJWS_sigvalBI BigInteger(defined in jsbn.js) object of JWS signature value
 * @property {String} parsedJWS_headS string of decoded JWS Header
 * @property {String} parsedJWS_headS string of decoded JWS Payload
 * @author Kenji Urushima
 * @version 1.1 (07 May 2012)
 * @requires base64x.js, json-sans-eval.js and jsrsasign library
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
KJUR.jws.JWS = function() {

    // === utility =============================================================
    /**
     * check whether a String "s" is a safe JSON string or not.<br/>
     * If a String "s" is a malformed JSON string or an other object type
     * this returns 0, otherwise this returns 1.
     * @name isSafeJSONString
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} s JSON string
     * @return {Number} 1 or 0
     */
    this.isSafeJSONString = function(s, h, p) {
	var o = null;
	try {
	    o = jsonParse(s);
	    if (typeof o != "object") return 0;
	    if (o.constructor === Array) return 0;
	    if (h) h[p] = o;
	    return 1;
	} catch (ex) {
	    return 0;
	}
    };

    /**
     * read a String "s" as JSON object if it is safe.<br/>
     * If a String "s" is a malformed JSON string or not JSON string,
     * this returns null, otherwise returns JSON object.
     * @name readSafeJSONString
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} s JSON string
     * @return {Object} JSON object or null
     * @since 1.1.1
     */
    this.readSafeJSONString = function(s) {
	var o = null;
	try {
	    o = jsonParse(s);
	    if (typeof o != "object") return null;
	    if (o.constructor === Array) return null;
	    return o;
	} catch (ex) {
	    return null;
	}
    };

    /**
     * get Encoed Signature Value from JWS string.<br/>
     * @name getEncodedSignatureValueFromJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @return {String} string of Encoded Signature Value 
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     */
    this.getEncodedSignatureValueFromJWS = function(sJWS) {
	if (sJWS.match(/^[^.]+\.[^.]+\.([^.]*)$/) === null) {
	    throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
	}
	return RegExp.$1;
    };

    /**
     * parse JWS string and set public property 'parsedJWS' dictionary.<br/>
     * @name parseJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be parsed.
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since 1.1
     */
    this.parseJWS = function(sJWS, sigValNotNeeded) {
	if ((this.parsedJWS !== undefined) &&
	    (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined))) {
	    return;
	}
	if (sJWS.match(/^([^.]+)\.([^.]+)\.([^.]*)$/) === null) {
	    throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
	}
	var b6Head = RegExp.$1;
	var b6Payload = RegExp.$2;
	var b6SigVal = RegExp.$3;
	var sSI = b6Head + "." + b6Payload;
	this.parsedJWS = {};
	this.parsedJWS.headB64U = b6Head;
	this.parsedJWS.payloadB64U = b6Payload;
	this.parsedJWS.sigvalB64U = b6SigVal;
	this.parsedJWS.si = sSI;

	if (!sigValNotNeeded) {
	    var hSigVal = b64utohex(b6SigVal);
	    var biSigVal = parseBigInt(hSigVal, 16);
	    this.parsedJWS.sigvalH = hSigVal;
	    this.parsedJWS.sigvalBI = biSigVal;
	}

	var sHead = b64utoutf8(b6Head);
	var sPayload = b64utoutf8(b6Payload);
	this.parsedJWS.headS = sHead;
	this.parsedJWS.payloadS = sPayload;

	if (! this.isSafeJSONString(sHead, this.parsedJWS, 'headP'))
	    throw "malformed JSON string for JWS Head: " + sHead;
    };

    // ==== JWS Validation =========================================================
    function _getSignatureInputByString(sHead, sPayload) {
	return utf8tob64u(sHead) + "." + utf8tob64u(sPayload);
    }

    function _getHashBySignatureInput(sSignatureInput, sHashAlg) {
	var hashfunc = function(s) { return KJUR.crypto.Util.hashString(s, sHashAlg); };
	if (hashfunc === null) throw "hash function not defined in jsrsasign: " + sHashAlg;
	return hashfunc(sSignatureInput);
    }

    function _jws_verifySignature(sHead, sPayload, hSig, hN, hE) {
	var sSignatureInput = _getSignatureInputByString(sHead, sPayload);
	var biSig = parseBigInt(hSig, 16);
	return _rsasign_verifySignatureWithArgs(sSignatureInput, biSig, hN, hE);
    }

    /**
     * verify JWS signature with naked RSA public key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name verifyJWSByNE
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {String} hN hexadecimal string for modulus of RSA public key
     * @param {String} hE hexadecimal string for public exponent of RSA public key
     * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     */
    this.verifyJWSByNE = function(sJWS, hN, hE) {
	this.parseJWS(sJWS);
	return _rsasign_verifySignatureWithArgs(this.parsedJWS.si, this.parsedJWS.sigvalBI, hN, hE);    
    };

    /**
     * verify JWS signature with RSA public key.<br/>
     * This only supports "RS256", "RS512", "PS256" and "PS512" algorithms.
     * @name verifyJWSByKey
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {RSAKey} key RSA public key
     * @return {Boolean} returns true when JWS signature is valid, otherwise returns false
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     */
    this.verifyJWSByKey = function(sJWS, key, allowed_algs) {
	this.parseJWS(sJWS, (!key) || !key.verifyString);
    var headP = this.parsedJWS.headP;
    var alg = headP.alg;
    if (alg === undefined)
    {
        throw new Error('alg not present');
    }
    allowed_algs = allowed_algs || [];
    function is_allowed(a)
    {
        if (Array.isArray(allowed_algs))
        {
            return allowed_algs.indexOf(a) >= 0;
        }
        else
        {
            return allowed_algs[a] !== undefined;
        }
    }
    if (!is_allowed(alg))
    {
        throw new Error('algorithm not allowed: ' + alg);
    }

    if (alg === 'none')
    {
        return true;
    }
    if (!key)
    {
        if (!is_allowed('none'))
        {
            throw new Error('no key but none alg not allowed');
        }
        return true;
    }

    var hashAlg = _jws_getHashAlgFromParsedHead(headP);
    alg = alg.substr(0, 2);
    var isPSS = alg === "PS";
    var r;

	if (key.hashAndVerify) {
	    r = key.hashAndVerify(hashAlg,
				     new Buffer(this.parsedJWS.si, 'utf8'),
				     new Buffer(b64utob64(this.parsedJWS.sigvalB64U), 'base64'),
				     null,
				     isPSS);
	} else if (isPSS) {
	    r = key.verifyStringPSS(this.parsedJWS.si,
				       this.parsedJWS.sigvalH, hashAlg);
	} else if (alg === "HS") {
        r = const_time_equal(hmac(hashAlg, key, this.parsedJWS.si), b64utob64(this.parsedJWS.sigvalB64U));
    } else {
	    r = key.verifyString(this.parsedJWS.si,
				    this.parsedJWS.sigvalH);
	}
    if (!r)
    {
        throw new Error('failed to verify');
    }
    return r;
    };

    /**
     * verify JWS signature by PEM formatted X.509 certificate.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name verifyJWSByPemX509Cert
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {String} sPemX509Cert string of PEM formatted X.509 certificate
     * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since 1.1
     */
    this.verifyJWSByPemX509Cert = function(sJWS, sPemX509Cert) {
	this.parseJWS(sJWS);
	var x509 = new X509();
	x509.readCertPEM(sPemX509Cert);
	return x509.subjectPublicKeyRSA.verifyString(this.parsedJWS.si, this.parsedJWS.sigvalH);
    };

    // ==== JWS Generation =========================================================
    var supported_algos = {
        RS256: true, RS512: true,
        PS256: true, PS512: true,
        HS256: true, HS512: true
    };

    function _jws_getHashAlgFromParsedHead(head) {
	var sigAlg = head.alg;
	var hashAlg = "";

	if (!supported_algos[sigAlg])
	    throw "JWS signature algorithm not supported: " + sigAlg;
	if (sigAlg.substr(2) == "256") hashAlg = "sha256";
	if (sigAlg.substr(2) == "512") hashAlg = "sha512";
	return hashAlg;
    }

    function _jws_getHashAlgFromHead(sHead) {
	return _jws_getHashAlgFromParsedHead(jsonParse(sHead));
    }

    function _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD) {
	var rsa = new RSAKey();
	rsa.setPrivate(hN, hE, hD);

	var hashAlg = _jws_getHashAlgFromHead(sHead);
	var sigValue = rsa.signString(sSI, hashAlg);
	return sigValue;
    }

    function _jws_generateSignatureValueBySI_Key(headP, sPayload, sSI, key) {
    var alg = headP.alg;

    if (alg === 'none') {
        return '';
    }

    var hashAlg = _jws_getHashAlgFromParsedHead(headP);

	alg = alg.substr(0, 2);

    var isPSS = alg === "PS";

	if (key.hashAndSign) {
	    return b64tob64u(key.hashAndSign(hashAlg, sSI, 'utf8', 'base64', isPSS));
	} else if (isPSS) {
	    return hextob64u(key.signStringPSS(sSI, hashAlg));
	} else if (alg === "HS") {
        return b64tob64u(hmac(hashAlg, key, sSI));
    } else {
	    return hextob64u(key.signString(sSI, hashAlg));
	}
    }

    function _jws_generateSignatureValueByNED(sHead, sPayload, hN, hE, hD) {
	var sSI = _getSignatureInputByString(sHead, sPayload);
	return _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
    }

    /**
     * generate JWS signature by Header, Payload and a naked RSA private key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name generateJWSByNED
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sHead string of JWS Header
     * @param {String} sPayload string of JWS Payload
     * @param {String} hN hexadecimal string for modulus of RSA public key
     * @param {String} hE hexadecimal string for public exponent of RSA public key
     * @param {String} hD hexadecimal string for private exponent of RSA private key
     * @return {String} JWS signature string
     * @throws if sHead is a malformed JSON string.
     * @throws if supported signature algorithm was not specified in JSON Header.
     */
    this.generateJWSByNED = function(sHead, sPayload, hN, hE, hD) {
	if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var hSigValue = _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
	var b64SigValue = hextob64u(hSigValue);
	
	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

    /**
     * generate JWS signature by Header, Payload and a RSA private key.<br/>
     * This only supports "RS256", "RS512", "PS256" and "PS512" algorithms.
     * @name generateJWSByKey
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sHead string of JWS Header
     * @param {String} sPayload string of JWS Payload
     * @param {RSAKey} RSA private key
     * @return {String} JWS signature string
     * @throws if sHead is a malformed JSON string.
     * @throws if supported signature algorithm was not specified in JSON Header.
     */
    this.generateJWSByKey = function(sHead, sPayload, key) {
	var obj = {};
	if (!this.isSafeJSONString(sHead, obj, 'headP'))
	    throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var b64SigValue = _jws_generateSignatureValueBySI_Key(obj.headP, sPayload, sSI, key);

	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

    // === sign with PKCS#1 RSA private key =====================================================
    function _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey) {
	var rsa = new RSAKey();
	rsa.readPrivateKeyFromPEMString(sPemPrvKey);
	var hashAlg = _jws_getHashAlgFromHead(sHead);
	var sigValue = rsa.signString(sSI, hashAlg);
	return sigValue;
    }

    /**
     * generate JWS signature by Header, Payload and a PEM formatted PKCS#1 RSA private key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name generateJWSByP1PrvKey
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sHead string of JWS Header
     * @param {String} sPayload string of JWS Payload
     * @param {String} string for sPemPrvKey PEM formatted PKCS#1 RSA private key<br/>
     *                 Heading and trailing space characters in PEM key will be ignored.
     * @return {String} JWS signature string
     * @throws if sHead is a malformed JSON string.
     * @throws if supported signature algorithm was not specified in JSON Header.
     * @since 1.1
     */
    this.generateJWSByP1PrvKey = function(sHead, sPayload, sPemPrvKey) {
	if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var hSigValue = _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey);
	var b64SigValue = hextob64u(hSigValue);

	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

};
/*global RSAKey: false,
         KJUR: false,
         jsonParse: false,
         utf8tob64u: true,
         SecureRandom: false,
         BAtohex: false,
         ASN1HEX: false */
/*jslint nomen: true, node: true, newcap: true, forin: true */
"use strict";

var _prvKeyHead = "-----BEGIN RSA PRIVATE KEY-----";
var _prvKeyFoot = "-----END RSA PRIVATE KEY-----";
var _pubKeyHead = "-----BEGIN PUBLIC KEY-----";
var _pubKeyFoot = "-----END PUBLIC KEY-----";
/*jslint regexp: true */
var _re_pem = /(.{1,64})/g;
/*jslint regexp: false */

function _rsapem_extractEncodedData2(sPEMKey)
{
    var s = sPEMKey;
    s = s.replace(_prvKeyHead, "");
    s = s.replace(_prvKeyFoot, "");
    s = s.replace(_pubKeyHead, "");
    s = s.replace(_pubKeyFoot, "");
    s = s.replace(/[ \n]+/g, "");
    return s;
}

RSAKey.prototype.readPrivateKeyFromPEMString = function (keyPEM)
{
    return this.readPrivateKeyFromPkcs1PemString(_rsapem_extractEncodedData2(keyPEM));
};

RSAKey.prototype.readPublicKeyFromPEMString = function (keyPEM)
{
    return this.readPublicKeyFromX509PEMString(_rsapem_extractEncodedData2(keyPEM));
};

RSAKey.prototype.privateKeyToPEMString = function ()
{
    return _prvKeyHead + '\n' +
           this.privateKeyToPkcs1PemString().replace(_re_pem, '$1\n') +
           _prvKeyFoot + '\n';
};

RSAKey.prototype.publicKeyToPEMString = function ()
{
    return _pubKeyHead + '\n' +
           this.publicKeyToX509PemString().replace(_re_pem, '$1\n') +
           _pubKeyFoot + '\n';
};

function _asnhex_getStartPosOfV_AtObj(s, pos)
{
    return ASN1HEX.getStartPosOfV_AtObj(s, pos);
}

function _asnhex_getPosOfNextSibling_AtObj(s, pos)
{
    return ASN1HEX.getPosOfNextSibling_AtObj(s, pos);
}

function _asnhex_getHexOfV_AtObj(s, pos)
{
    return ASN1HEX.getHexOfV_AtObj(s, pos);
}

KJUR.jws._orig_JWS = KJUR.jws.JWS;

KJUR.jws.JWS = function ()
{
    KJUR.jws._orig_JWS.call(this);

    this._orig_isSafeJSONString = this.isSafeJSONString;

    this.isSafeJSONString = function (s, h, p)
    {
        if (typeof s !== "string")
        {
            if (h)
            {
                h[p] = s;
            }

            return 1;
        }

        return this._orig_isSafeJSONString(s, h, p);
    };
};

KJUR.jws.JWS.prototype.getUnparsedHeader = function ()
{
    return this.parsedJWS && this.parsedJWS.headS;
};

KJUR.jws.JWS.prototype.getUnparsedPayload = function ()
{
    return this.parsedJWS && this.parsedJWS.payloadS;
};

KJUR.jws.JWS.prototype.getParsedHeader = function ()
{
    if (this.parsedJWS)
    {
        if (!this.parsedJWS.headP && this.parsedJWS.headS)
        {
            this.parsedJWS.headP = jsonParse(this.parsedJWS.headS);
        }

        return this.parsedJWS.headP;
    }

    return undefined;
};

KJUR.jws.JWS.prototype.getParsedPayload = function ()
{
    if (this.parsedJWS)
    {
        if (!this.parsedJWS.payloadP && this.parsedJWS.payloadS)
        {
            this.parsedJWS.payloadP = jsonParse(this.parsedJWS.payloadS);
        }

        return this.parsedJWS.payloadP;
    }

    return undefined;
};

KJUR.jws.JWS.prototype.processJWS = function (jws)
{
    this.parseJWS(jws, true);
};

var _orig_utf8tob64u = utf8tob64u;

utf8tob64u = function (s)
{
    return _orig_utf8tob64u(typeof s !== "string" ? JSON.stringify(s) : s);
};

KJUR.jws.JWT = function ()
{
    KJUR.jws.JWS.apply(this, arguments);
};

KJUR.jws.JWT.prototype = Object.create(KJUR.jws.JWS.prototype);

KJUR.jws.JWT.prototype.generateJWTByKey = function (header, claims, expires, not_before, jti_size, key)
{
    if (key === undefined)
    {
        key = jti_size;
        jti_size = 16;
    }

    if (key === undefined)
    {
        key = not_before;
        not_before = null;
    }

    var new_header = {}, new_claims = {}, x, jti, now;
    
    for (x in header)
    {
        new_header[x] = header[x];
    }

    if (!key)
    {
        new_header.alg = 'none';
    }

    new_header.typ = 'JWT';

    for (x in claims)
    {
        new_claims[x] = claims[x];
    }

    now = new Date();
    
    not_before = not_before || now;

    if (jti_size)
    {
        jti = [];
        jti.length = jti_size;
        new SecureRandom().nextBytes(jti);
        new_claims.jti = BAtohex(jti);
    }

    new_claims.iat = Math.floor(now.getTime() / 1000);
    new_claims.nbf = Math.floor(not_before.getTime() / 1000);
    new_claims.exp = Math.floor(expires.getTime() / 1000);

    return this.generateJWSByKey(new_header, new_claims, key);
};

KJUR.jws.JWT.prototype.verifyJWTByKey = function (jwt, options, key, allowed_algs)
{
    if (allowed_algs === undefined)
    {
        allowed_algs = key;
        key = options;
        options = null;
    }

    this.verifyJWSByKey(jwt, key, allowed_algs);

    options = options || {};

    var header = this.getParsedHeader(),
        claims = this.getParsedPayload(),
        now = Math.floor(new Date().getTime() / 1000),
        iat_skew = options.iat_skew || 0;

    if (!header)
    {
        throw new Error('no header');
    }

    if (!claims)
    {
        throw new Error('no claims');
    }

    if (header.typ === undefined)
    {
        if (!options.checks_optional)
        {
            throw new Error('no type claim');
        }
    }
    else if (header.typ !== 'JWT')
    {
        throw new Error('type is not JWT');
    }

    if (claims.iat === undefined)
    {
        if (!options.checks_optional)
        {
            throw new Error('no issued at claim');
        }
    }
    else if (claims.iat > (now + iat_skew))
    {
        throw new Error('issued in the future');
    }

    if (claims.nbf === undefined)
    {
        if (!options.checks_optional)
        {
            throw new Error('no not before claim');
        }
    }
    else if (claims.nbf > now)
    {
        throw new Error('not yet valid');
    }

    if (claims.exp === undefined)
    {
        if (!options.checks_optional)
        {
            throw new Error("no expires claim");
        }
    }
    else if (claims.exp <= now)
    {
        throw new Error("expired");
    }

    return true;
};
/*global RSAKey: false,
         KJUR: false,
         X509: false */
/*jslint node: true */

var util = require('util'),
    crypto = require('crypto'),
    keypair = require('keypair');

exports.SlowRSAKey = RSAKey;
exports.JWS = KJUR.jws.JWS;
exports.JWT = KJUR.jws.JWT;
exports.X509 = X509;

function PublicKey(public_pem)
{
    this._public_pem = public_pem;
}

PublicKey.prototype.toPublicPem = function ()
{
    return this._public_pem;
};

PublicKey.prototype.hashAndVerify = function (algorithm,
                                              buf,
                                              sig,
                                              encoding,
                                              use_pss_padding,
                                              salt_len)
{
    var key = { key: this.toPublicPem() };

    if (use_pss_padding)
    {
        key.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        if (salt_len === undefined)
        {
            key.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
        }
        else
        {
            key.saltLength = salt_len;
        }
    }
    else
    {
        key.padding = crypto.constants.RSA_PKCS1_PADDING;
    }

    return crypto.createVerify('RSA-' + algorithm.toUpperCase())
            .update(buf, encoding)
            .verify(key, sig, encoding);

};

function PrivateKey(private_pem, password)
{
    PublicKey.call(this);
    this._private_pem = private_pem;
    this._password = password;
}

util.inherits(PrivateKey, PublicKey);

PrivateKey.prototype.toPrivatePem = function ()
{
    return this._private_pem;
};

PrivateKey.prototype.toPublicPem = function ()
{
    if (!this._public_pem)
    {
        var key = new RSAKey();
        key.readPrivateKeyFromPEMString(this._private_pem);
        this._public_pem = key.publicKeyToPEMString();
    }

    return this._public_pem;
};

PrivateKey.prototype.hashAndSign = function (algorithm,
                                             buf, bufEncoding,
                                             outEncoding,
                                             use_pss_padding, salt_len)
{
    var key = { key: this.toPrivatePem() };

    if (this._password !== undefined)
    {
        key.passphrase = this._password;
    }

    if (use_pss_padding)
    {
        key.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        if (salt_len === undefined)
        {
            key.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
        }
        else
        {
            key.saltLength = salt_len;
        }
    }
    else
    {
        key.padding = crypto.constants.RSA_PKCS1_PADDING;
    }

    return crypto.createSign('RSA-' + algorithm.toUpperCase())
            .update(buf, bufEncoding)
            .sign(key, outEncoding);
};

exports.createPublicKey = function (public_pem)
{
    return new PublicKey(public_pem);
};

exports.createPrivateKey = function (private_pem, password)
{
    return new PrivateKey(private_pem, password);
};

try
{
    var turbokey = require('bindings')('turbokey.node');

    exports.generatePrivateKey = function (modulusBits, exponent)
    {
        return new PrivateKey(turbokey.generatePrivateKey(modulusBits, exponent));
    };
}
catch (e)
{
    console.error(e.message);
    console.error('Falling back to slow path (keypair)');

    exports.generatePrivateKey = function (modulusBits, exponent)
    {
        return new PrivateKey(keypair(
        {
            bits: modulusBits,
            exponent: exponent
        }).private);
    };
}

