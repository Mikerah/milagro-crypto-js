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


/* Test FP4 ARITHMETICS - test driver and function exerciser for FP4 API Functions */

var chai = require('chai');

var CTX = require("../index");

var expect = chai.expect;

var pf_curves = ['BN254', 'BN254CX', 'BLS381', 'BLS383', 'BLS461', 'FP256BN', 'FP512BN'];

var readBIG = function(string, ctx) {
    while (string.length != ctx.BIG.MODBYTES*2){string = "00"+string;}
    return ctx.BIG.fromBytes(Buffer.from(string, "hex"));
}

var readFP2 = function(string, ctx) {
    string = string.split(",");
    var cox = string[0].slice(1);
    var coy = string[1].slice(0,-1);

    var x = readBIG(cox,ctx);
    var y = readBIG(coy,ctx);

    return new ctx.FP2(x,y);;
}

var readFP4 = function(string, ctx) {
    var X, Y;

    string = string.split("],[");
    var cox = string[0].slice(1) + "]";
    var coy = "[" + string[1].slice(0,-1);

    X = readFP2(cox,ctx);
    Y = readFP2(coy,ctx);

    return new ctx.FP4(X,Y);
}

describe('TEST FP4 ARITHMETIC', function() {

    pf_curves.forEach(function(curve){

        it('test '+ curve, function(done) {
            this.timeout(0);

            var ctx = new CTX(curve);
            var vectors = require('../testVectors/fp4/'+curve+'.json');
            var i=0;

            vectors.forEach(function(vector){

                // test commutativity of addition
                var fp41 = readFP4(vector.FP41,ctx);
                var fp42 = readFP4(vector.FP42,ctx);
                var fp4add = readFP4(vector.FP4add,ctx);

                var a1 = new ctx.FP4(0);
                var a2 = new ctx.FP4(0);
                a1.copy(fp41);
                a2.copy(fp42);
                a1.add(a2);
                expect(a1.toString()).to.equal(fp4add.toString());
                a1.copy(fp41);
                a2.add(a1);
                expect(a2.toString()).to.equal(fp4add.toString());

                // test associativity of addition
                a2.add(fp4add);
                a1.copy(fp41);
                a1.add(fp4add);
                a1.add(fp42);
                expect(a1.toString()).to.equal(a2.toString());

                // test subtraction
                var fp4sub = readFP4(vector.FP4sub, ctx);
                a1.copy(fp41);
                a2.copy(fp42);
                a1.sub(a2);
                expect(a1.toString()).to.equal(fp4sub.toString());

                // test negative of a FP4
                var fp4neg = readFP4(vector.FP4neg, ctx);
                a1.copy(fp41);
                a1.neg();
                expect(a1.toString()).to.equal(fp4neg.toString());

                // test conjugate of a FP4
                var fp4conj = readFP4(vector.FP4conj, ctx);
                a1.copy(fp41);
                a1.conj();
                expect(a1.toString()).to.equal(fp4conj.toString());

                // test negative conjugate of a FP4
                var fp4nconj = readFP4(vector.FP4nconj, ctx);
                a1.copy(fp41);
                a1.nconj();
                expect(a1.toString()).to.equal(fp4nconj.toString());

                // test multiplication by FP2
                var fp4pmul = readFP4(vector.FP4pmul, ctx);
                var fp2sc = readFP2(vector.FP2sc, ctx);
                a1.copy(fp41);
                a1.pmul(fp2sc);
                expect(a1.toString()).to.equal(fp4pmul.toString());

                // test small scalar multiplication
                var fp4imul = readFP4(vector.FP4imul, ctx);
                a1.copy(fp41);
                a1.imul(i);
                expect(a1.toString()).to.equal(fp4imul.toString());
                i++;

                // test square
                var fp4sqr = readFP4(vector.FP4sqr, ctx);
                a1.copy(fp41);
                a1.sqr();
                expect(a1.toString()).to.equal(fp4sqr.toString());

                // test multiplication
                var fp4mul = readFP4(vector.FP4mul, ctx);
                a1.copy(fp41);
                a2.copy(fp42);
                a1.mul(a2);
                expect(a1.toString()).to.equal(fp4mul.toString());

                // test power
                var fp4pow = readFP4(vector.FP4pow, ctx);
                var BIGsc1 = readBIG(vector.BIGsc1, ctx);
                BIGsc1.norm();
                a1.copy(fp41);
                a1 = a1.pow(BIGsc1);
                expect(a1.toString()).to.equal(fp4pow.toString());

                // test inverse
                var fp4inv = readFP4(vector.FP4inv, ctx);
                a1.copy(fp41);
                a1.inverse();
                expect(a1.toString()).to.equal(fp4inv.toString());

                // test multiplication by sqrt(1+sqrt(-1))
                var fp4mulj = readFP4(vector.FP4mulj, ctx);
                a1.copy(fp41);
                a1.times_i();
                expect(a1.toString()).to.equal(fp4mulj.toString());

                // // test the XTR addition function r=w*x-conj(x)*y+z
                var fp4xtrA = readFP4(vector.FP4xtrA, ctx);
                a1.copy(fp42);
                a1.xtr_A(fp41,fp4add,fp4sub);
                expect(a1.toString()).to.equal(fp4xtrA.toString());

                // test the XTR addition function r=w*x-conj(x)*y+z
                var fp4xtrD = readFP4(vector.FP4xtrD, ctx);
                a1.copy(fp41);
                a1.xtr_D();
                expect(a1.toString()).to.equal(fp4xtrD.toString());

                // test the XTR single power r=Tr(x^e)
                var fp4xtrpow = readFP4(vector.FP4xtrpow, ctx);
                var fp121 = readFP4(vector.FP121, ctx);
                a1 = fp121.xtr_pow(BIGsc1);
                expect(a1.toString()).to.equal(fp4xtrpow.toString());

                // test the XTR double power r=Tr(x^e)
                var fp4xtrpow2 = readFP4(vector.FP4xtrpow2, ctx);
                var fp122 = readFP4(vector.FP122, ctx);
                var fp123 = readFP4(vector.FP123, ctx);
                var fp124 = readFP4(vector.FP124, ctx);
                var BIGsc2 = readBIG(vector.BIGsc2, ctx);
                a1 = fp121.xtr_pow2(fp122,fp123,fp124,BIGsc2,BIGsc1);
                expect(a1.toString()).to.equal(fp4xtrpow2.toString());
            });
            done();
        });
    });
});
