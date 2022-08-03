import * as alg from "./alg";

export type AesBlockSize = 128 | 192 | 256;

export interface EnforcedRsaHashedKeyGenParams extends RsaHashedKeyGenParams {
    name: alg.RSA.Variants;
    hash: alg.SHA.SecureVariants;
    modulusLength: 2048 | 4096;
}

export interface EnforcedEcKeyGenParams extends EcKeyGenParams {
    name: alg.EC.Variants;
    namedCurve: alg.EC.Curves;
}

export interface EnforcedAesKeyGenParams extends AesKeyGenParams {
    name: alg.AES.Modes;
    length: AesBlockSize;
}

export interface EnforcedHmacKeyGenParams extends HmacKeyGenParams {
    name: alg.Authentication.Code.HMAC;
    hash: alg.SHA.SecureVariants;
    length?: 512 | 1024;
}

export interface EnforcedRsaHashedImportParams extends RsaHashedImportParams {
    name: alg.RSA.Variants;
    hash: alg.SHA.SecureVariants;
}

export interface EnforcedEcKeyImportParams extends EcKeyImportParams {
    name: alg.EC.Variants;
    namedCurve: alg.EC.Curves;
}

export interface EnforcedHmacImportParams extends HmacImportParams {
    name: alg.Authentication.Code.HMAC;
    hash: alg.SHA.SecureVariants;
    length?: 512 | 1024;
}

export interface EnforcedRsaOaepParams extends RsaOaepParams {
    name: alg.RSA.Variant.RSA_OAEP;
}

export interface EnforcedRsaPssParams extends RsaPssParams {
    name: alg.RSA.Variant.RSA_PSS;
}
export interface EnforcedRsassaPkcs1v15Params extends Algorithm {
    name: alg.RSA.Variant.RSASSA_PKCS1_v1_5;
}

export interface EnforcedEcdsaParams extends EcdsaParams {
    name: alg.EC.Variant.ECDSA;
    hash: alg.SHA.SecureVariants;
}

export interface EnforcedEcdhKeyDeriveParams extends EcdhKeyDeriveParams {
    name: alg.EC.Variant.ECDH;
}

export interface AesGcmKeyAlgorithm extends AesKeyAlgorithm {
    name: alg.AES.Mode.AES_GCM;
    length: AesBlockSize;
}

export interface EnforcedAesGcmParams extends AesGcmParams {
    tagLength?: 32 | 64 | 96 | 104 | 112 | 120 | 128;
}

export interface AesCtrKeyAlgorithm extends AesKeyAlgorithm {
    name: alg.AES.Mode.AES_CTR;
    length: AesBlockSize;
}

export interface EnforcedAesCtrParams extends AesCtrParams {
    name: alg.AES.Mode.AES_CTR;
}

export interface AesCbcKeyAlgorithm extends AesKeyAlgorithm {
    name: alg.AES.Mode.AES_CBC;
    length: AesBlockSize;
}

export interface EnforcedAesCbcParams extends AesCbcParams {
    name: alg.AES.Mode.AES_CBC;
}

export interface AesKwKeyAlgorithm extends KeyAlgorithm {
    name: alg.AES.Mode.AES_KW;
}

export interface EnforcedAesKwParams {
    name: alg.AES.Mode.AES_KW;
}

export interface EnforcedHkdfParams extends HkdfParams {
    name: alg.KDF.Variant.HKDF;
    hash: alg.SHA.SecureVariants;
}
export interface EnforcedPbkdf2Params extends Pbkdf2Params {
    name: alg.KDF.Variant.PBKDF2;
    hash: alg.SHA.SecureVariants;
    iterations: 720_000 | 310_000 | 310_000 | 120_000;
}

export type EnforcedAesKeyAlgorithms =
    | AesGcmKeyAlgorithm
    | AesCtrKeyAlgorithm
    | AesCbcKeyAlgorithm
    | AesKwKeyAlgorithm;
export type EnforcedAesKeyAlgorithmNames = Pick<
    EnforcedAesKeyAlgorithms,
    "name"
>;
export type EnforcedAesParams =
    | EnforcedAesGcmParams
    | EnforcedAesCtrParams
    | EnforcedAesCbcParams
    | EnforcedAesKwParams;
export type EnforcedImportParams =
    | EnforcedRsaHashedImportParams
    | EnforcedEcKeyImportParams
    | EnforcedHmacImportParams
    | EnforcedAesKeyAlgorithmNames;
export type EnforcedKeyGenParams =
    | EnforcedRsaHashedKeyGenParams
    | EnforcedEcKeyGenParams
    | EnforcedHmacKeyGenParams
    | EnforcedAesKeyGenParams;
export type EnforcedKeyDeriveParams =
    | EnforcedEcdhKeyDeriveParams
    | EnforcedHkdfParams
    | EnforcedPbkdf2Params;
