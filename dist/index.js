"use strict";
exports.__esModule = true;
exports.unSerializeIdentity = exports.serializeIdentity = exports.genIdentityCommitment = exports.genIdentity = void 0;
var crypto = require("crypto");
var circomlib = require('circomlib');
var bigintConversion = require("bigint-conversion");
var utils = require("ffjavascript").utils;
var pedersenHash = function (ints) {
    var p = circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(Buffer.concat(ints.map(function (x) { return Buffer.from(utils.leInt2Buff(x, 32)); }))));
    return BigInt(p[0]);
};
var genRandomBuffer = function (numBytes) {
    if (numBytes === void 0) { numBytes = 32; }
    return crypto.randomBytes(numBytes);
};
var genPubKey = function (privKey) {
    return circomlib.eddsa.prv2pub(privKey);
};
var genEddsaKeyPair = function (privKey) {
    if (privKey === void 0) { privKey = genRandomBuffer(); }
    var pubKey = genPubKey(privKey);
    return { pubKey: pubKey, privKey: privKey };
};
var genIdentity = function (privKey) {
    if (privKey === void 0) { privKey = genRandomBuffer(32); }
    return {
        keypair: genEddsaKeyPair(privKey),
        identityNullifier: bigintConversion.bufToBigint(genRandomBuffer(31)),
        identityTrapdoor: bigintConversion.bufToBigint(genRandomBuffer(31))
    };
};
exports.genIdentity = genIdentity;
var genIdentityCommitment = function (identity) {
    return pedersenHash([
        circomlib.babyJub.mulPointEscalar(identity.keypair.pubKey, 8)[0],
        identity.identityNullifier,
        identity.identityTrapdoor,
    ]);
};
exports.genIdentityCommitment = genIdentityCommitment;
var serializeIdentity = function (identity) {
    var data = [
        identity.keypair.privKey.toString('hex'),
        identity.identityNullifier.toString(16),
        identity.identityTrapdoor.toString(16),
    ];
    return JSON.stringify(data);
};
exports.serializeIdentity = serializeIdentity;
var unSerializeIdentity = function (serialisedIdentity) {
    var data = JSON.parse(serialisedIdentity);
    return {
        keypair: genEddsaKeyPair(Buffer.from(data[0], 'hex')),
        identityNullifier: bigintConversion.hexToBigint(data[1]),
        identityTrapdoor: bigintConversion.hexToBigint(data[2])
    };
};
exports.unSerializeIdentity = unSerializeIdentity;
//# sourceMappingURL=index.js.map