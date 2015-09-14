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
