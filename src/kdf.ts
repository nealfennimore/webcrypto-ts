import { DeriveKeyUsagePair, getKeyUsagePairsByAlg } from "./keyUsages";
import * as alg from "./alg";
import * as params from "./params";
import type { AesKey } from "./aes";
import { WebCrypto } from "./crypto";

export interface Pbkdf2KeyMaterial extends CryptoKey {}

export interface HkdfKeyMaterial extends CryptoKey {}
export interface HmacKey extends CryptoKey {}

export namespace KDF {
    export async function generateKeyMaterial<K extends CryptoKey>(
        format: KeyFormat,
        keyData: BufferSource,
        algorithm: alg.KDF.Variants,
        extractable: boolean = false
    ): Promise<K> {
        return await WebCrypto.importKey(
            format as any,
            keyData,
            algorithm,
            extractable,
            DeriveKeyUsagePair
        );
    }

    export async function deriveKey(
        algorithm: params.EnforcedPbkdf2Params | params.EnforcedHkdfParams,
        baseKey: Pbkdf2KeyMaterial | HkdfKeyMaterial,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey | HmacKey> {
        return await WebCrypto.deriveKey<
            AesKey | HmacKey,
            params.EnforcedAesKeyGenParams | params.EnforcedHmacKeyGenParams
        >(
            algorithm,
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
        );
    }

    export async function deriveBits(
        algorithm: params.EnforcedPbkdf2Params | params.EnforcedHkdfParams,
        baseKey: Pbkdf2KeyMaterial | HkdfKeyMaterial,
        length: number
    ): Promise<ArrayBuffer> {
        return await WebCrypto.deriveBits(algorithm, baseKey, length);
    }
}

export namespace PBKDF2 {
    const hashIterations: Record<alg.SHA.SecureVariants, number> = {
        "SHA-256": 310_000,
        "SHA-384": 310_000,
        "SHA-512": 120_000,
    };

    export const generateKeyMaterial = (
        format: KeyFormat,
        keyData: BufferSource,
        extractable?: boolean
    ) =>
        KDF.generateKeyMaterial<Pbkdf2KeyMaterial>(
            format,
            keyData,
            alg.KDF.Variant.PBKDF2,
            extractable
        );

    export const deriveKey = (
        baseKey: Pbkdf2KeyMaterial,
        salt: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        KDF.deriveKey(
            {
                name: alg.KDF.Variant.PBKDF2,
                hash: hashAlgorithm,
                salt,
                iterations: hashIterations[hashAlgorithm] as any,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages
        );

    export const deriveBits = (
        baseKey: Pbkdf2KeyMaterial,
        salt: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        length: number
    ) =>
        KDF.deriveBits(
            {
                name: alg.KDF.Variant.PBKDF2,
                hash: hashAlgorithm,
                salt,
                iterations: hashIterations[hashAlgorithm] as any,
            },
            baseKey,
            length
        );
}
export namespace HKDF {
    export const generateKeyMaterial = (
        format: KeyFormat,
        keyData: BufferSource,
        extractable?: boolean
    ) =>
        KDF.generateKeyMaterial<HkdfKeyMaterial>(
            format,
            keyData,
            alg.KDF.Variant.HKDF,
            extractable
        );

    export const deriveKey = (
        baseKey: HkdfKeyMaterial,
        salt: BufferSource,
        info: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        KDF.deriveKey(
            {
                name: alg.KDF.Variant.HKDF,
                hash: hashAlgorithm,
                salt,
                info,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages
        );

    export const deriveBits = (
        baseKey: HkdfKeyMaterial,
        salt: BufferSource,
        info: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        length: number
    ) =>
        KDF.deriveBits(
            {
                name: alg.KDF.Variant.HKDF,
                hash: hashAlgorithm,
                salt,
                info,
            },
            baseKey,
            length
        );
}
