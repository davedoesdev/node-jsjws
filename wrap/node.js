/*jslint node: true */
"use strict";

var KJUR;

var navigator = {
  appName: "Netscape"
};

var jsonParse = JSON.parse;

var crypto = require('crypto'),
    util = require('util');

function SecureRandom()
{
}

SecureRandom.prototype.nextBytes = function (ba)
{
    var rb = crypto.randomBytes(ba.length), i;

    for (i = 0; i < ba.length; i += 1)
    {
        ba[i] = rb[i];
    }
};

var YAHOO = {
    lang: {
        extend: function (constructor, superConstructor)
        {
            util.inherits(constructor, superConstructor);
            constructor.superclass = {
                constructor: superConstructor
            };
        }
    }
};
