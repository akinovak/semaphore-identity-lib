import * as crypto from 'crypto';
const circomlib = require('circomlib');
import * as bigintConversion from 'bigint-conversion';
const utils = require("ffjavascript").utils;

type EddsaPrivateKey = Buffer;
type EddsaPublicKey = bigint[];

interface Identity {
    keypair: EddsaKeyPair,
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

interface EddsaKeyPair {
    pubKey: EddsaPublicKey,
    privKey: EddsaPrivateKey,
}

const pedersenHash = (ints: bigint[]): bigint => {
    const p = circomlib.babyJub.unpackPoint(
        circomlib.pedersenHash.hash(
            Buffer.concat(
                ints.map((x) => utils.leInt2Buff(x, 32))
            )
        )
    )
    return BigInt(p[0])
}

const genRandomBuffer = (numBytes: number = 32): Buffer => {
    return crypto.randomBytes(numBytes)
}

const genPubKey = (privKey: EddsaPrivateKey): EddsaPublicKey => {
    return circomlib.eddsa.prv2pub(privKey)
}

const genEddsaKeyPair = (privKey: Buffer = genRandomBuffer()): EddsaKeyPair => {
    const pubKey = genPubKey(privKey)
    return { pubKey, privKey }
}

const genIdentity = (
    privKey: Buffer = genRandomBuffer(32),
): Identity => {
    return {
        keypair: genEddsaKeyPair(privKey),
        identityNullifier: bigintConversion.bufToBigint(genRandomBuffer(31)),
        identityTrapdoor: bigintConversion.bufToBigint(genRandomBuffer(31)),
    }
}

const genIdentityCommitment = (
    identity: Identity,
): bigint => {

    return pedersenHash([
        circomlib.babyJub.mulPointEscalar(identity.keypair.pubKey, 8)[0],
        identity.identityNullifier,
        identity.identityTrapdoor,
    ])
}

const serializeIdentity = (
    identity: Identity,
): string => {
    const data = [
        identity.keypair.privKey.toString('hex'),
        identity.identityNullifier.toString(16),
        identity.identityTrapdoor.toString(16),
    ]
    return JSON.stringify(data)
}

const unSerializeIdentity = (serialisedIdentity: string): Identity => {
    const data = JSON.parse(serialisedIdentity)
    return {
        keypair: genEddsaKeyPair(Buffer.from(data[0], 'hex')),
        identityNullifier: bigintConversion.hexToBigint(data[1]),
        identityTrapdoor: bigintConversion.hexToBigint(data[2]),
    }
}

export { 
    Identity, 
    genIdentity, 
    genIdentityCommitment,
    serializeIdentity, 
    unSerializeIdentity
}