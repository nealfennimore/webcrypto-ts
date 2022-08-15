/**
 * Enforced parameters for algorithms
 * @module
 */
import { Alg as AES } from "./aes/shared.js";
import { Alg as EC, EcdhPubCryptoKey } from "./ec/shared.js";
import { Alg as Authentication } from "./hmac/index.js";
import { Alg as KDF } from "./kdf/shared.js";
import { Alg as RSA } from "./rsa/shared.js";
import { Alg as SHA } from "./sha/shared.js";

export type AesBlockSize = 128 | 192 | 256;

export interface EnforcedRsaHashedKeyGenParams extends RsaHashedKeyGenParams {
    name: RSA.Variants;
    hash: SHA.SecureVariants;
    modulusLength: 2048 | 4096;
}

export interface EnforcedEcKeyGenParams extends EcKeyGenParams {
    name: EC.Variants;
    namedCurve: EC.Curves;
}

export interface EnforcedAesKeyGenParams extends AesKeyGenParams {
    name: AES.Modes;
    length: AesBlockSize;
}

export interface EnforcedHmacKeyGenParams extends HmacKeyGenParams {
    name: Authentication.Code.HMAC;
    hash: SHA.SecureVariants;
    length?: 512 | 1024;
}

export interface EnforcedRsaHashedImportParams extends RsaHashedImportParams {
    name: RSA.Variants;
    hash: SHA.SecureVariants;
}

export interface EnforcedEcKeyImportParams extends EcKeyImportParams {
    name: EC.Variants;
    namedCurve: EC.Curves;
}

export interface EnforcedHmacImportParams extends HmacImportParams {
    name: Authentication.Code.HMAC;
    hash: SHA.SecureVariants;
    length?: 512 | 1024;
}

export interface EnforcedRsaOaepParams extends RsaOaepParams {
    name: RSA.Variant.RSA_OAEP;
}

export interface EnforcedRsaPssParams extends RsaPssParams {
    name: RSA.Variant.RSA_PSS;
}
export interface EnforcedRsassaPkcs1v15Params extends Algorithm {
    name: RSA.Variant.RSASSA_PKCS1_v1_5;
}

export interface EnforcedEcdsaParams extends EcdsaParams {
    name: EC.Variant.ECDSA;
    hash: SHA.SecureVariants;
}

export interface EnforcedEcdhKeyDeriveParams extends EcdhKeyDeriveParams {
    name: EC.Variant.ECDH;
    public: EcdhPubCryptoKey;
}

export interface AesGcmKeyAlgorithm extends AesKeyAlgorithm {
    name: AES.Mode.AES_GCM;
    length: AesBlockSize;
}

export interface EnforcedAesGcmParams extends AesGcmParams {
    tagLength?: 32 | 64 | 96 | 104 | 112 | 120 | 128;
}

export interface AesCtrKeyAlgorithm extends AesKeyAlgorithm {
    name: AES.Mode.AES_CTR;
    length: AesBlockSize;
}

export interface EnforcedAesCtrParams extends AesCtrParams {
    name: AES.Mode.AES_CTR;
}

export interface AesCbcKeyAlgorithm extends AesKeyAlgorithm {
    name: AES.Mode.AES_CBC;
    length: AesBlockSize;
}

export interface EnforcedAesCbcParams extends AesCbcParams {
    name: AES.Mode.AES_CBC;
}

export interface AesKwKeyAlgorithm extends KeyAlgorithm {
    name: AES.Mode.AES_KW;
}

export interface EnforcedAesKwParams {
    name: AES.Mode.AES_KW;
}

export interface EnforcedHkdfParams extends HkdfParams {
    name: KDF.Variant.HKDF;
    hash: SHA.SecureVariants;
}
export interface EnforcedPbkdf2Params extends Pbkdf2Params {
    name: KDF.Variant.PBKDF2;
    hash: SHA.SecureVariants;
    iterations: 720_000 | 310_000 | 310_000 | 120_000;
}

export interface HmacKeyAlgorithm extends KeyAlgorithm {
    name: Authentication.Code.HMAC;
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
