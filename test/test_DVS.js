/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either exprtns or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/* Test DVS - test driver and function exerciser for Designated Veifier Signature API Functions */

var chai = require('chai');

var CTX = require("../index");

pf_curves = ['BN254', 'BN254CX', 'BLS383', 'BLS461', 'FP256BN', 'FP512BN'];

var expect = chai.expect;

pf_curves.forEach(function(curve) {

    var ctx = new CTX(curve);

    describe('TEST DVS ' + curve, function() {

        var rng = new ctx.RAND();
        var sha = ctx.ECP.HASH_TYPE;

        var pin = 1234,
            pin2 = 2345,
            IDstr = "testuser@miracl.com",
            message = "Message to sign",
            S = [],
            SST = [],
            TOKEN = [],
            SEC = [],
            xID = [],
            X = [],
            Y1 = [],
            Y2 = [],
            Z = [],
            Pa = [],
            U = [],
            CLIENT_ID, rtn, date, timeValue;

        before(function(done) {
            this.timeout(0);

            var RAW = [];
            rng.clean();
            for (i = 0; i < 100; i++) RAW[i] = i;
            rng.seed(100, RAW);

            /* Trusted Authority set-up */
            ctx.MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = ctx.MPIN.stringtobytes(IDstr);

            /* Generate ctx.RANDom public key and z */
            ctx.MPIN.GET_DVS_KEYPAIR(rng, Z, Pa);

            /* Append Pa to ID */
            for (var i = 0; i < Pa.length; i++)
                CLIENT_ID.push(Pa[i]);

            /* Hash Client ID */
            HCID = ctx.MPIN.HASH_ID(sha, CLIENT_ID);

            /* Client and Server are issued secrets by DTA */
            ctx.MPIN.GET_SERVER_SECRET(S, SST);
            ctx.MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Compute client secret for key escrow less scheme z.CS */
            ctx.MPIN.GET_G1_MULTIPLE(null, 0, Z, TOKEN, TOKEN);

            /* Client extracts PIN from secret to create Token */
            ctx.MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);

            done();
        });

        it('test Good Signature', function(done) {
            this.timeout(0);

            date = 0;
            timeValue = ctx.MPIN.GET_TIME();

            rtn = ctx.MPIN.CLIENT(sha, 0, CLIENT_ID, rng, X, pin, TOKEN, SEC, U, null, null, timeValue, Y1, message);
            expect(rtn).to.be.equal(0);

            /* Server  */
            rtn = ctx.MPIN.SERVER(sha, 0, xID, null, Y2, SST, U, null, SEC, null, null, CLIENT_ID, timeValue, message, Pa);
            expect(rtn).to.be.equal(0);
            done();
        });

        it('test Bad Signature', function(done) {
            this.timeout(0);

            date = 0;
            timeValue = ctx.MPIN.GET_TIME();

            rtn = ctx.MPIN.CLIENT(sha, 0, CLIENT_ID, rng, X, pin2, TOKEN, SEC, U, null, null, timeValue, Y1, message);
            expect(rtn).to.be.equal(0);

            /* Server  */
            rtn = ctx.MPIN.SERVER(sha, 0, xID, null, Y2, SST, U, null, SEC, null, null, CLIENT_ID, timeValue, message, Pa);
            expect(rtn).to.be.equal(ctx.MPIN.BAD_PIN);
            done();
        });
    });
});