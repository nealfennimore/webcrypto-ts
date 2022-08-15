import { AES, Authentication, EC, KDF, RSA } from "./alg.js";

export enum KeyFormats {
    raw = "raw",
    pkcs8 = "pkcs8",
    spki = "spki",
    jwk = "jwk",
}

export enum KeyUsages {
    encrypt = "encrypt",
    decrypt = "decrypt",
    sign = "sign",
    verify = "verify",
    deriveKey = "deriveKey",
    deriveBits = "deriveBits",
    wrapKey = "wrapKey",
    unwrapKey = "unwrapKey",
}

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

export type KeyUsagePairs =
    | EncryptionKeyUsagePair
    | SigningKeyUsagePair
    | WrappingKeyUsagePair
    | DeriveKeyUsagePair;

export function getKeyUsagePairsByAlg(alg: string): KeyUsagePair {
    switch (alg) {
        case AES.Mode.AES_CBC:
        case AES.Mode.AES_CTR:
        case AES.Mode.AES_GCM:
        case RSA.Variant.RSA_OAEP:
            return EncryptionKeyUsagePair;

        case Authentication.Code.HMAC:
        case EC.Variant.ECDSA:
        case RSA.Variant.RSA_PSS:
        case RSA.Variant.RSASSA_PKCS1_v1_5:
            return SigningKeyUsagePair;

        case EC.Variant.ECDH:
        case KDF.Variant.HKDF:
        case KDF.Variant.PBKDF2:
            return DeriveKeyUsagePair;

        case AES.Mode.AES_KW:
            return WrappingKeyUsagePair;
        default:
            throw new Error(`Invalid alg ${alg}`);
    }
}
