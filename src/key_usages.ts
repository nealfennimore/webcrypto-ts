/**
 * Key usages and allowed formats
 * @module
 */

import { Alg as AES } from "./aes/shared.js";
import { Alg as CURVE25519 } from "./curve25519/shared.js";
import { Alg as CURVE448 } from "./curve448/shared.js";
import { Alg as EC } from "./ec/shared.js";
import { Alg as Authentication } from "./hmac/index.js";
import { Alg as KDF } from "./kdf/shared.js";
import { Alg as KMAC } from "./kmac/shared.js";
import { Alg as MLDSA } from "./ml_dsa/shared.js";
import { Alg as MLKEM } from "./ml_kem/shared.js";
import { Alg as RSA } from "./rsa/shared.js";

export enum KeyFormats {
    raw = "raw",
    pkcs8 = "pkcs8",
    spki = "spki",
    jwk = "jwk",
    raw_secret = "raw-secret",
    raw_public = "raw-public",
    raw_seed = "raw-seed",
}

/**
 * `KeyFormat` plus the formats added by the Modern Algorithms in the
 * Web Cryptography API spec (`raw-secret`, `raw-public`, `raw-seed`).
 * Requires Node.js 24.7.0 or higher.
 */
export type ExtendedKeyFormat = `${KeyFormats}`;

export enum KeyUsages {
    encrypt = "encrypt",
    decrypt = "decrypt",
    sign = "sign",
    verify = "verify",
    deriveKey = "deriveKey",
    deriveBits = "deriveBits",
    wrapKey = "wrapKey",
    unwrapKey = "unwrapKey",
    encapsulateKey = "encapsulateKey",
    decapsulateKey = "decapsulateKey",
    encapsulateBits = "encapsulateBits",
    decapsulateBits = "decapsulateBits",
}

/**
 * `KeyUsage` plus the key encapsulation usages added by the Modern
 * Algorithms in the Web Cryptography API spec. Requires Node.js 24.7.0
 * or higher.
 */
export type ExtendedKeyUsage = `${KeyUsages}`;

export type KeyUsagePair = [KeyUsage, KeyUsage];

export type EncryptionKeyUsagePair = [KeyUsages.encrypt, KeyUsages.decrypt];
export const EncryptionKeyUsagePair: KeyUsagePair = [
    KeyUsages.encrypt,
    KeyUsages.decrypt,
];
export type SigningKeyUsagePair = [KeyUsages.sign, KeyUsages.verify];
export const SigningKeyUsagePair: KeyUsagePair = [
    KeyUsages.sign,
    KeyUsages.verify,
];
export type WrappingKeyUsagePair = [KeyUsages.wrapKey, KeyUsages.unwrapKey];
export const WrappingKeyUsagePair: KeyUsagePair = [
    KeyUsages.wrapKey,
    KeyUsages.unwrapKey,
];
export type DeriveKeyUsagePair = [KeyUsages.deriveKey, KeyUsages.deriveBits];
export const DeriveKeyUsagePair: KeyUsagePair = [
    KeyUsages.deriveKey,
    KeyUsages.deriveBits,
];
export type EncapsulationKeyUsages = [
    KeyUsages.encapsulateKey,
    KeyUsages.decapsulateKey,
    KeyUsages.encapsulateBits,
    KeyUsages.decapsulateBits
];
export const EncapsulationKeyUsages: EncapsulationKeyUsages = [
    KeyUsages.encapsulateKey,
    KeyUsages.decapsulateKey,
    KeyUsages.encapsulateBits,
    KeyUsages.decapsulateBits,
];

export type KeyUsagePairs =
    | EncryptionKeyUsagePair
    | SigningKeyUsagePair
    | WrappingKeyUsagePair
    | DeriveKeyUsagePair;

/**
 * Given a algorithm, return the _most likely_ key usages.
 */
export function getKeyUsagePairsByAlg(alg: string): ExtendedKeyUsage[] {
    switch (alg) {
        case AES.Mode.AES_CBC:
        case AES.Mode.AES_CTR:
        case AES.Mode.AES_GCM:
        case RSA.Variant.RSA_OAEP:
            return EncryptionKeyUsagePair;

        case Authentication.Code.HMAC:
        case KMAC.Code.KMAC128:
        case KMAC.Code.KMAC256:
        case EC.Variant.ECDSA:
        case CURVE25519.Variant.Ed25519:
        case CURVE448.Variant.Ed448:
        case MLDSA.Variant.ML_DSA_44:
        case MLDSA.Variant.ML_DSA_65:
        case MLDSA.Variant.ML_DSA_87:
        case RSA.Variant.RSA_PSS:
        case RSA.Variant.RSASSA_PKCS1_v1_5:
            return SigningKeyUsagePair;

        case EC.Variant.ECDH:
        case CURVE25519.Variant.X25519:
        case CURVE448.Variant.X448:
        case KDF.Variant.HKDF:
        case KDF.Variant.PBKDF2:
            return DeriveKeyUsagePair;

        case AES.Mode.AES_KW:
            return WrappingKeyUsagePair;

        case MLKEM.Variant.ML_KEM_512:
        case MLKEM.Variant.ML_KEM_768:
        case MLKEM.Variant.ML_KEM_1024:
            return EncapsulationKeyUsages;
        default:
            throw new Error(`Invalid alg ${alg}`);
    }
}
