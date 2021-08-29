import * as lib from 'libsemaphore';
import * as newLib from '../src';

const identity = lib.genIdentity();

const libIdCommitment = lib.genIdentityCommitment(identity);
const newLibIdCommitmnet = newLib.genIdentityCommitment(identity);

const libSerialized = lib.serialiseIdentity(identity);
const newLibSerialized = newLib.serializeIdentity(identity);

const libUnserialized = lib.unSerialiseIdentity(libSerialized);
const newLibUnserialized = newLib.unSerializeIdentity(libSerialized);

// expect()

console.log(libIdCommitment === libIdCommitment);
console.log(libSerialized === newLibSerialized)

console.log(libUnserialized.identityNullifier == newLibUnserialized.identityNullifier)
console.log(libUnserialized.identityTrapdoor == newLibUnserialized.identityTrapdoor)
console.log(libUnserialized.keypair.pubKey[0] == newLibUnserialized.keypair.pubKey[0])
console.log(libUnserialized.keypair.pubKey[1] == newLibUnserialized.keypair.pubKey[1])

console.log(Buffer.compare(libUnserialized.keypair.privKey, newLibUnserialized.keypair.privKey) === 0);
