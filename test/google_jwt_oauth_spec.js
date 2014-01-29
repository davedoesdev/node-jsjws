/*global expect: false,
         it: false,
         jsjws: false,
         describe: false,
         beforeEach: false,
         afterEach: false,
         sinon: false */
/*jslint node: true */
"use strict";

// JWT from https://developers.google.com/accounts/docs/OAuth2ServiceAccount
var google_jwt_example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiI3NjEzMjY3OTgwNjktcjVtbGpsbG4xcmQ0bHJiaGc3NWVmZ2lncDM2bTc4ajVAZGV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvcHJlZGljdGlvbiIsImF1ZCI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsImV4cCI6MTMyODU1NDM4NSwiaWF0IjoxMzI4NTUwNzg1fQ.ixOUGehweEVX_UKXv5BbbwVEdcz6AYS-6uQV6fGorGKrHf3LIJnyREw9evE-gs2bmMaQI5_UbabvI4k-mQE4kBqtmSpTzxYBL1TCd7Kv5nTZoUC1CmwmWCFqT9RE6D7XSgPUh_jF1qskLa2w0rxMSjwruNKbysgRNctZPln7cqQ";

describe('google-jwt-oauth', function ()
{
    var adjust, clock;

    beforeEach(function ()
    {
        adjust = new Date().getTime() / 1000;
        clock = sinon.useFakeTimers();
    });

    afterEach(function ()
    {
        clock.restore();
    });

    it('should fail to verify the token because of missing claims', function ()
    {
        clock.restore();

        var jwt = new jsjws.JWT();

        expect(function ()
        {
            jwt.verifyJWTByKey(google_jwt_example, null);
        }).to.throw('no not before claim');
    });

    it('should verify the token without requiring all claims', function ()
    {
        var jwt = new jsjws.JWT();

        expect(jwt.verifyJWTByKey(google_jwt_example,
        {
            iat_skew: adjust,
            checks_optional: true
        }, null)).to.equal(true);

        expect(jwt.getParsedHeader()).to.eql(
        {
            alg: 'RS256',
            typ: 'JWT'
        });

        expect(jwt.getParsedPayload()).to.eql(
        {
            iss: '761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com',
            scope: 'https://www.googleapis.com/auth/prediction',
            aud: 'https://accounts.google.com/o/oauth2/token',
            exp: 1328554385,
            iat: 1328550785
        });
    });
});
