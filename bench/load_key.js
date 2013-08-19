/*global implementation: false,
         priv_pem: false */
/*jslint node: true, unparam: true */
"use strict";

module.exports = function (i, done)
{
    implementation.loadkey(priv_pem, function (err)
    {
        if (err)
        {
            throw err;
        }

        done();
    });
};

