/**
 * Enforced parameters for algorithms
 * @module
 */
import { Alg as AES } from "./aes/shared.js";
import {
    Alg as CURVE25519,
    X25519PubCryptoKey,
} from "./curve25519/shared.js";
import { Alg as CURVE448, X448PubCryptoKey } from "./curve448/shared.js";
import { Alg as EC, EcdhPubCryptoKey } from "./ec/shared.js";
import { Alg as Authentication } from "./hmac/index.js";
import { Alg as KDF } from "./kdf/shared.js";
import { Alg as KMAC } from "./kmac/shared.js";
import { Alg as MLDSA } from "./ml_dsa/shared.js";
import { Alg as MLKEM } from "./ml_kem/shared.js";
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

export interface EnforcedCurve25519KeyGenParams extends Algorithm {
    name: CURVE25519.Variants;
}

export interface EnforcedCurve448KeyGenParams extends Algorithm {
    name: CURVE448.Variants;
}

export interface EnforcedMlDsaKeyGenParams extends Algorithm {
    name: MLDSA.Variants;
}

export interface EnforcedMlKemKeyGenParams extends Algorithm {
    name: MLKEM.Variants;
}

export interface EnforcedKmacKeyGenParams extends Algorithm {
    name: KMAC.Codes;
    /**
     * The number of bits in the generated KMAC key. If omitted, the
     * length is determined by the KMAC algorithm used.
     */
    length?: number;
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

export interface EnforcedCurve25519KeyImportParams extends Algorithm {
    name: CURVE25519.Variants;
}

export interface EnforcedCurve448KeyImportParams extends Algorithm {
    name: CURVE448.Variants;
}

export interface EnforcedMlDsaImportParams extends Algorithm {
    name: MLDSA.Variants;
}

export interface EnforcedMlKemImportParams extends Algorithm {
    name: MLKEM.Variants;
}

export interface EnforcedKmacImportParams extends Algorithm {
    name: KMAC.Codes;
    /**
     * The number of bits in the KMAC key. This is optional and should
     * be omitted for most cases.
     */
    length?: number;
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

export interface EnforcedEd25519Params extends Algorithm {
    name: CURVE25519.Variant.Ed25519;
}

export interface EnforcedX25519KeyDeriveParams extends EcdhKeyDeriveParams {
    name: CURVE25519.Variant.X25519;
    public: X25519PubCryptoKey;
}

export interface EnforcedEd448Params extends Algorithm {
    name: CURVE448.Variant.Ed448;
    /**
     * Optional context data to associate with the message.
     * Non-empty context requires Node.js 24.8.0 or higher.
     */
    context?: BufferSource;
}

export interface EnforcedX448KeyDeriveParams extends EcdhKeyDeriveParams {
    name: CURVE448.Variant.X448;
    public: X448PubCryptoKey;
}

export interface EnforcedMlDsaSignParams extends Algorithm {
    name: MLDSA.Variants;
    /**
     * Optional context data to associate with the message.
     */
    context?: BufferSource;
}

export interface EnforcedMlKemEncapsulateParams extends Algorithm {
    name: MLKEM.Variants;
}

export interface EnforcedKmacParams extends Algorithm {
    name: KMAC.Codes;
    /**
     * The length of the MAC output in bits. Must be a multiple of 8.
     * Note that the Node.js docs claim bytes, but the implementation
     * treats it as bits (`outputLength / 8` bytes are produced).
     */
    outputLength: number;
    /**
     * Optional customization string.
     */
    customization?: BufferSource;
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
    hash: SHA.Variants;
    iterations: 1_300_000 | 600_000 | 600_000 | 210_000;
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
    | EnforcedCurve25519KeyImportParams
    | EnforcedCurve448KeyImportParams
    | EnforcedMlDsaImportParams
    | EnforcedMlKemImportParams
    | EnforcedHmacImportParams
    | EnforcedKmacImportParams
    | EnforcedAesKeyAlgorithmNames;
export type EnforcedKeyGenParams =
    | EnforcedRsaHashedKeyGenParams
    | EnforcedEcKeyGenParams
    | EnforcedCurve25519KeyGenParams
    | EnforcedCurve448KeyGenParams
    | EnforcedMlDsaKeyGenParams
    | EnforcedMlKemKeyGenParams
    | EnforcedHmacKeyGenParams
    | EnforcedKmacKeyGenParams
    | EnforcedAesKeyGenParams;
export type EnforcedKeyDeriveParams =
    | EnforcedEcdhKeyDeriveParams
    | EnforcedX25519KeyDeriveParams
    | EnforcedX448KeyDeriveParams
    | EnforcedHkdfParams
    | EnforcedPbkdf2Params;
