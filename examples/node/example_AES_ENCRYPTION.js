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

/* Test HASH function - test driver and function exerciser for SHA256, SHA384, SHA512 API Functions */

var CTX = require("../../index");

var ctx = new CTX();


var AES_ENCRYPT = function(mode, K, M) {
    /* Input is from an octet string M, output is to an octet string C */
    /* Input is padded as necessary to make up a full final block */
    var a = new ctx.AES();
    var fin;
    var i, j, ipt, opt;
    var buff = [];
    /*var clen=16+(Math.floor(M.length/16))*16;*/

    var C = [];
    var padlen;

    a.init(mode, K.length, K, null);

    ipt = opt = 0;
    fin = false;
    for (;;) {
        for (i = 0; i < 16; i++) {
            if (ipt < M.length) {
                buff[i] = M[ipt++];
            } else {
                fin = true;
                break;
            }
        }
        if (fin) {
            break;
        }
        a.encrypt(buff);
        for (i = 0; i < 16; i++) {
            C[opt++] = buff[i];
        }
    }

    /* last block, filled up to i-th index */

    padlen = 16 - i;
    for (j = i; j < 16; j++) {
        buff[j] = padlen;
    }
    a.encrypt(buff);
    for (i = 0; i < 16; i++) {
        C[opt++] = buff[i];
    }
    a.end();
    return C;
};

var KEY = "edfdb257cb37cdf182c5455b0c0efebb";

console.log("Encryption Key: ", KEY);

var PLAINTEXT = "1695fe475421cace3557daca01f445ff";

console.log("Plaintext: ", PLAINTEXT);

var Cout = AES_ENCRYPT(ctx.AES.ECB, ctx.Utils.hextobytes(KEY), ctx.Utils.hextobytes(PLAINTEXT));

console.log("Ciphertext: ", ctx.Utils.bytestohex(Cout));
