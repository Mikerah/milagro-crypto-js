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
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/* Test MPIN - test driver and function exerciser for MPIN API Functions */

var CTX = require("../index");

var chai = require('chai');

var expect = chai.expect;

// Curves for consistency test
var pf_curves = ['BN254', 'BN254CX', 'BLS383', 'BLS461', 'FP256BN', 'FP512BN','BLS24','BLS48'];

// Curves for test with test vectors
var tv_curves = ['BN254CX'];

hextobytes = function(value_hex) {
    // "use strict";
    var len, byte_value, i;

    len = value_hex.length;
    byte_value = [];

    for (i = 0; i < len; i += 2) {
        byte_value[(i / 2)] = parseInt(value_hex.substr(i, 2), 16);
    }
    return byte_value;
};

for (var i = pf_curves.length - 1; i >= 0; i--) {

    describe('TEST MPIN ' + pf_curves[i], function() {

        var ctx = new CTX(pf_curves[i]),
            rng = new ctx.RAND(),
            MPIN,

            EAS = 16,
            EGS, EFS,
            G1S = 2 * EFS + 1,
            G2S,

            S = [],
            SST = [],
            TOKEN = [],
            PERMIT = [],
            SEC = [],
            xID = [],
            xCID = [],
            X = [],
            Y = [],
            E = [],
            F = [],
            HCID = [],
            HID = [],
            HTID = [],

            G1 = [],
            G2 = [],
            R = [],
            Z = [],
            W = [],
            T = [],
            CK = [],
            SK = [],

            HSID = [],

            sha = ctx.ECP.HASH_TYPE,

            IDstr = "testUser@miracl.com",
            CLIENT_ID, date, pin;

        if (ctx.ECP.CURVE_PAIRING_TYPE === 1 | ctx.ECP.CURVE_PAIRING_TYPE === 2) {
            MPIN = ctx.MPIN;
            G2S = 4 * EFS;
        } else if (ctx.ECP.CURVE_PAIRING_TYPE === 3) {
            MPIN = ctx.MPIN192;
            G2S = 8 * EFS;
        } else if (ctx.ECP.CURVE_PAIRING_TYPE === 4) {
            MPIN = ctx.MPIN256;
            G2S = 16 * EFS;
        }

        EGS = MPIN.EGS;
        EFS = MPIN.EFS;

        before(function(done) {
            var RAW = [];
            rng.clean();
            for (var j = 0; j < 100; j++) RAW[j] = j;
            rng.seed(100, RAW);
            done();
        });

        it('test MPin', function(done) {
            this.timeout(0);

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);
            MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            pin = 1234;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
            expect(rtn).to.be.equal(0);

            date = 0;
            pin = 1234;

            var pxID = xID;
            var pHID = HID;
            var prHID = pHID;

            rtn = MPIN.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, null, null);
            expect(rtn).to.be.equal(0);

            /* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
            MPIN.SERVER_1(sha, date, CLIENT_ID, pHID, null);

            /* Server generates Random number Y and sends it to Client */
            MPIN.RANDOM_GENERATE(rng, Y);

            /* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
            rtn = MPIN.CLIENT_2(X, Y, SEC);
            expect(rtn).to.be.equal(0);

            /* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
            /* If PIN error not required, set E and F = NULL */
            rtn = MPIN.SERVER_2(date, pHID, null, Y, SST, pxID, null, SEC, null, null);
            expect(rtn).to.be.equal(0);
            done();
        });

        it('test MPin Time Permits', function(done) {
            this.timeout(0);

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);
            MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            pin = 1234;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
            expect(rtn).to.be.equal(0);

            date = MPIN.today();
            /* Client gets "Time Token" permit from DTA */
            MPIN.GET_CLIENT_PERMIT(sha, date, S, HCID, PERMIT);

            /* This encoding makes Time permit look random - Elligator squared */
            MPIN.ENCODING(rng, PERMIT);
            MPIN.DECODING(PERMIT);

            pin = 1234;

            var pxCID = xCID;
            var pHID = HID;
            var pHTID = HTID;
            var pPERMIT = PERMIT;
            var prHID = pHTID;
            var pxID = null;

            rtn = MPIN.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, pxCID, pPERMIT);
            expect(rtn).to.be.equal(0);

            /* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
            MPIN.SERVER_1(sha, date, CLIENT_ID, pHID, pHTID);

            /* Server generates Random number Y and sends it to Client */
            MPIN.RANDOM_GENERATE(rng, Y);

            /* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
            rtn = MPIN.CLIENT_2(X, Y, SEC);
            expect(rtn).to.be.equal(0);

            /* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
            /* If PIN error not required, set E and F = NULL */
            rtn = MPIN.SERVER_2(date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, null, null);
            expect(rtn).to.be.equal(0);

            done();

        });

        it('test MPin Full One Pass', function(done) {
            this.timeout(0);

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);

            MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            pin = 1234;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
            expect(rtn).to.be.equal(0);

            MPIN.PRECOMPUTE(TOKEN, HCID, G1, G2);

            date = 0;
            pin = 1234;

            var pxID = xID;
            var pxCID = null;
            var pHID = HID;
            var pHTID = null;
            var pE = null;
            var pF = null;
            var pPERMIT = null;
            var prHID = pHID;

            timeValue = MPIN.GET_TIME();

            rtn = MPIN.CLIENT(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, pxCID, pPERMIT, timeValue, Y);
            expect(rtn).to.be.equal(0);

            HCID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 1, R, HCID, Z); /* Also Send Z=r.ID to Server, remember random r */

            rtn = MPIN.SERVER(sha, date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, pE, pF, CLIENT_ID, timeValue);
            expect(rtn).to.be.equal(0);

            HSID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 0, W, prHID, T); /* Also send T=w.ID to client, remember random w  */

            H = MPIN.HASH_ALL(sha, HCID, pxID, pxCID, SEC, Y, Z, T);
            MPIN.CLIENT_KEY(sha, G1, G2, pin, R, X, H, T, CK);

            H = MPIN.HASH_ALL(sha, HSID, pxID, pxCID, SEC, Y, Z, T);
            MPIN.SERVER_KEY(sha, Z, SST, W, H, pHID, pxID, pxCID, SK);
            expect(MPIN.bytestostring(CK)).to.be.equal(MPIN.bytestostring(SK));

            done();
        });

		it('test MPin bad token', function(done) {
            this.timeout(0);

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);
            MPIN.RANDOM_GENERATE(rng, T);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);

            MPIN.GET_CLIENT_SECRET(T, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            pin = 1234;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
            expect(rtn).to.be.equal(0);

            MPIN.PRECOMPUTE(TOKEN, HCID, G1, G2);

            date = 0;
            pin = 1234;

            var pxID = xID;
            var pxCID = null;
            var pHID = HID;
            var pHTID = null;
            var pPERMIT = null;
            var prHID = pHID;

            timeValue = MPIN.GET_TIME();

            rtn = MPIN.CLIENT(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, pxCID, pPERMIT, timeValue, Y);
            expect(rtn).to.be.equal(0);

            HCID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 1, R, HCID, Z); /* Also Send Z=r.ID to Server, remember random r */

            rtn = MPIN.SERVER(sha, date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, null, null, CLIENT_ID, timeValue);
            expect(rtn).to.be.equal(MPIN.BAD_PIN);

            done();
        });

      	it('test MPin bad PIN', function(done) {
            this.timeout(0);

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);

            MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            var pin1 = 5555;
            var pin2 = 4444;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin1, TOKEN);
            expect(rtn).to.be.equal(0);

            MPIN.PRECOMPUTE(TOKEN, HCID, G1, G2);

            date = 0;

            var pxID = xID;
            var pxCID = null;
            var pHID = HID;
            var pHTID = null;
            var pPERMIT = null;
            var prHID = pHID;

            timeValue = MPIN.GET_TIME();

            rtn = MPIN.CLIENT(sha, date, CLIENT_ID, rng, X, pin2, TOKEN, SEC, pxID, pxCID, pPERMIT, timeValue, Y);
            expect(rtn).to.be.equal(0);

            HCID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 1, R, HCID, Z); /* Also Send Z=r.ID to Server, remember random r */

            rtn = MPIN.SERVER(sha, date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, E, F, CLIENT_ID, timeValue);
            expect(rtn).to.be.equal(MPIN.BAD_PIN);

            // Retrieve PIN error
            rtn = MPIN.KANGAROO(E,F);
            expect(rtn).to.be.equal(pin2-pin1);

            done();
        });

        it('test MPin FUll Two Pass', function(done) {
            this.timeout(0);

            /* Set configuration */
            var PERMITS = true;

            /* Trusted Authority set-up */
            MPIN.RANDOM_GENERATE(rng, S);

            /* Create Client Identity */
            CLIENT_ID = MPIN.stringtobytes(IDstr);
            HCID = MPIN.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

            /* Client and Server are issued secrets by DTA */
            MPIN.GET_SERVER_SECRET(S, SST);
            MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);

            /* Client extracts PIN from secret to create Token */
            pin = 1234;
            rtn = MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
            expect(rtn).to.be.equal(0);

            MPIN.PRECOMPUTE(TOKEN, HCID, G1, G2);

            if (PERMITS) {
                date = MPIN.today();
                /* Client gets "Time Token" permit from DTA */
                MPIN.GET_CLIENT_PERMIT(sha, date, S, HCID, PERMIT);

                /* This encoding makes Time permit look random - Elligator squared */
                MPIN.ENCODING(rng, PERMIT);
                MPIN.DECODING(PERMIT);
            } else date = 0;

            pin = 1234;

            var pxID = xID;
            var pxCID = xCID;
            var pHID = HID;
            var pHTID = HTID;
            var pE = null;
            var pF = null;
            var pPERMIT = PERMIT;
            var prHID;

            if (date != 0) {
                prHID = pHTID;
                pxID = null;
            } else {
                prHID = pHID;
                pPERMIT = null;
                pxCID = null;
                pHTID = null;
            }

            rtn = MPIN.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, pxCID, pPERMIT);
            expect(rtn).to.be.equal(0);

            HCID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 1, R, HCID, Z); /* Also Send Z=r.ID to Server, remember random r */

            /* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
            MPIN.SERVER_1(sha, date, CLIENT_ID, pHID, pHTID);

            /* Server generates Random number Y and sends it to Client */
            MPIN.RANDOM_GENERATE(rng, Y);

            HSID = MPIN.HASH_ID(sha, CLIENT_ID);
            MPIN.GET_G1_MULTIPLE(rng, 0, W, prHID, T); /* Also send T=w.ID to client, remember random w  */

            /* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
            rtn = MPIN.CLIENT_2(X, Y, SEC);
            expect(rtn).to.be.equal(0);

            /* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
            /* If PIN error not required, set E and F = NULL */
            rtn = MPIN.SERVER_2(date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, pE, pF);
            expect(rtn).to.be.equal(0);

            H = MPIN.HASH_ALL(sha, HCID, pxID, pxCID, SEC, Y, Z, T);
            MPIN.CLIENT_KEY(sha, G1, G2, pin, R, X, H, T, CK);

            H = MPIN.HASH_ALL(sha, HSID, pxID, pxCID, SEC, Y, Z, T);
            MPIN.SERVER_KEY(sha, Z, SST, W, H, pHID, pxID, pxCID, SK);
            expect(MPIN.bytestostring(CK)).to.be.equal(MPIN.bytestostring(SK));

            done();
        });

      if (tv_curves.indexOf(pf_curves[i]) != -1) {
        var curve = pf_curves[i];

        it('test Combine Shares in G1 ' + curve + ' with Test Vectors', function(done) {
            this.timeout(0);
            // Load test vectors
            var vectors = require('../testVectors/mpin/MPIN_' + curve + '.json');

            var sha = ctx.ECP.HASH_TYPE;
            var CS = [];
            var TP = [];
            var TP1bytes = [];
            var TP2bytes = [];
            var TPbytes = [];
            var CS1bytes = [];
            var CS2bytes = [];
            var CSbytes = [];

            for (var vector in vectors) {

                  CS1bytes = hextobytes(vectors[vector].CS1);
                  CS2bytes = hextobytes(vectors[vector].CS2);
                  CSbytes = hextobytes(vectors[vector].CLIENT_SECRET);
                  MPIN.RECOMBINE_G1(CS1bytes, CS2bytes, CS);
                  expect(MPIN.comparebytes(CS,CSbytes)).to.be.equal(true);

                  TP1bytes = hextobytes(vectors[vector].TP1);
                  TP2bytes = hextobytes(vectors[vector].TP2);
                  TPbytes = hextobytes(vectors[vector].TIME_PERMIT);
                  MPIN.RECOMBINE_G1(TP1bytes, TP2bytes, TP);
                  expect(MPIN.comparebytes(TP,TPbytes)).to.be.equal(true);
            }
            done();
        });

        it('test MPin Two Passes ' + curve + ' with Test Vectors', function(done) {
            this.timeout(0);
            // Load test vectors
            var vectors = require('../testVectors/mpin/MPIN_' + curve + '.json');

            var sha = ctx.ECP.HASH_TYPE;
            var xID = [];
            var xCID = [];
            var SEC = [];
            var Y = [];

            for (var vector in vectors) {
                var rtn = MPIN.CLIENT_1(sha, vectors[vector].DATE, hextobytes(vectors[vector].MPIN_ID_HEX), null, hextobytes(vectors[vector].X), vectors[vector].PIN2, hextobytes(vectors[vector].TOKEN), SEC, xID, xCID, hextobytes(vectors[vector].TIME_PERMIT));
                expect(rtn).to.be.equal(0);
                expect(MPIN.bytestostring(xID)).to.be.equal(vectors[vector].U);
                expect(MPIN.bytestostring(xCID)).to.be.equal(vectors[vector].UT);

                var rtn = MPIN.CLIENT_2(hextobytes(vectors[vector].X), hextobytes(vectors[vector].Y), SEC);
                expect(rtn).to.be.equal(0);
                expect(MPIN.bytestostring(SEC)).to.be.equal(vectors[vector].V);
            }
            done();
        });

        it('test MPin One Pass ' + curve + ' with Test Vectors', function(done) {
            this.timeout(0);
            // Load test vectors
            var vectors = require('../testVectors/mpin/MPIN_ONE_PASS_' + curve + '.json');

            var sha = ctx.ECP.HASH_TYPE;
            var xID = [];
            var SEC = [];
            var Y = [];

            for (var vector in vectors) {
                var rtn = MPIN.CLIENT(sha, 0, hextobytes(vectors[vector].MPIN_ID_HEX), null, hextobytes(vectors[vector].X), vectors[vector].PIN2, hextobytes(vectors[vector].TOKEN), SEC, xID, null, null, vectors[vector].TimeValue, Y);
                expect(rtn).to.be.equal(0);
                expect(MPIN.bytestostring(xID)).to.be.equal(vectors[vector].U);
                expect(MPIN.bytestostring(SEC)).to.be.equal(vectors[vector].SEC);
            }
            done();
        });

      }

    });
}