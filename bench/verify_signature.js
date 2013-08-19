/*global implementation: false,
          browser_sigs: false */
/*jslint node: true, unparam: true */
"use strict";

module.exports = function (i, done)
{
    implementation.verify(browser_sigs.RS256, function (err, r)
    {
        if (err)
        {
            throw err;
        }

        if (!r)
        {
            throw "failed to verify";
        }

        done();
    });
};

