/*global implementation: false */
/*jslint node: true, unparam: true */
"use strict";

module.exports = function (i, done)
{
    implementation.genkey(2048, 65537, done);
};

