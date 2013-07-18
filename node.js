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
    "use strict";
    return undefined;
}

SecureRandom.prototype.nextBytes = function (ba)
{
    "use strict";

    var rb = crypto.randomBytes(ba.length), i;

    for (i = 0; i < ba.length; i += 1)
    {
        ba[i] = rb[i];
    }
};
