import { KeyUsagePairs, getKeyUsagePairsByAlg } from "./keyUsages";
import * as params from "./params";
import * as alg from "./alg";
import { WebCrypto } from "./crypto";

export interface RsaKey extends CryptoKey {}
export interface RsaKeyPair extends CryptoKeyPair {}

export namespace RSA {
    export async function generateKey(
        algorithm: params.EnforcedRsaHashedKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<RsaKey | RsaKeyPair> {
        return await WebCrypto.generateKey<
            RsaKey | RsaKeyPair,
            params.EnforcedRsaHashedKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: KeyFormat,
        algorithm: params.EnforcedRsaHashedImportParams,
        keyData: BufferSource | JsonWebKey,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<RsaKey> {
        return await WebCrypto.importKey<
            RsaKey,
            params.EnforcedRsaHashedImportParams
        >(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        keyData: RsaKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function sign(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(algorithm, keyData, data);
    }

    export async function verify(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(algorithm, keyData, signature, data);
    }
}

export namespace RSA_OAEP {
    export const generateKey = async (
        hash: alg.SHA.SecureVariants,
        modulusLength: 4096 = 4096,
        publicExponent: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]),
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.generateKey(
            {
                name: alg.RSA.Variant.RSA_OAEP,
                hash,
                modulusLength,
                publicExponent,
            },
            extractable,
            keyUsages
        );

    export const importKey = async (
        format: KeyFormat,
        hash: alg.SHA.SecureVariants,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.importKey(
            format,
            { name: alg.RSA.Variant.RSA_OAEP, hash },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = RSA.exportKey;

    export async function encrypt(
        algorithm: params.EnforcedRsaOaepParams,
        keyData: RsaKey,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.encrypt(algorithm, keyData, plaintext);
    }

    export async function decrypt(
        algorithm: params.EnforcedRsaOaepParams,
        keyData: RsaKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.decrypt(algorithm, keyData, ciphertext);
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: RsaKey,
        wrapAlgorithm: params.EnforcedRsaOaepParams
    ): Promise<ArrayBuffer> {
        return await WebCrypto.wrapKey(
            format as any,
            key,
            wrappingkey,
            wrapAlgorithm
        );
    }
    export async function unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: RsaKey,
        unwrappingKeyAlgorithm: params.EnforcedRsaOaepParams,
        extractable: boolean = true,
        keyUsages?: KeyUsagePairs
    ): Promise<CryptoKey> {
        return await WebCrypto.unwrapKey(
            format as any,
            wrappedKey,
            unwrappingKey,
            unwrappingKeyAlgorithm,
            wrappedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(wrappedKeyAlgorithm.name)
        );
    }
}

export namespace RSA_PSS {
    export const generateKey = async (
        hash: alg.SHA.SecureVariants,
        modulusLength: 4096 = 4096,
        publicExponent: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]),
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.generateKey(
            {
                name: alg.RSA.Variant.RSA_PSS,
                hash,
                modulusLength,
                publicExponent,
            },
            extractable,
            keyUsages
        );

    export const importKey = async (
        format: KeyFormat,
        hash: alg.SHA.SecureVariants,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.importKey(
            format,
            { name: alg.RSA.Variant.RSA_PSS, hash },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = RSA.exportKey;

    export const sign = async (
        saltLength: number,
        keyData: RsaKey,
        data: BufferSource
    ) =>
        await RSA.sign(
            {
                name: alg.RSA.Variant.RSA_PSS,
                saltLength,
            },
            keyData,
            data
        );

    export const verify = async (
        saltLength: number,
        keyData: RsaKey,
        signature: BufferSource,
        data: BufferSource
    ) =>
        await RSA.verify(
            {
                name: alg.RSA.Variant.RSA_PSS,
                saltLength,
            },
            keyData,
            signature,
            data
        );
}

export namespace RSASSA_PKCS1_v1_5 {
    export const generateKey = async (
        hash: alg.SHA.SecureVariants,
        modulusLength: 4096 = 4096,
        publicExponent: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]),
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.generateKey(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
                hash,
                modulusLength,
                publicExponent,
            },
            extractable,
            keyUsages
        );

    export const importKey = async (
        format: KeyFormat,
        hash: alg.SHA.SecureVariants,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RSA.importKey(
            format,
            { name: alg.RSA.Variant.RSASSA_PKCS1_v1_5, hash },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = RSA.exportKey;

    export const sign = async (keyData: RsaKey, data: BufferSource) =>
        await RSA.sign(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            keyData,
            data
        );

    export const verify = async (
        keyData: RsaKey,
        signature: BufferSource,
        data: BufferSource
    ) =>
        await RSA.verify(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            keyData,
            signature,
            data
        );
}
