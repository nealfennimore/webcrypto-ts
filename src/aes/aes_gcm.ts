/**
 * Code related to AES_GCM
 * @module
 */
import * as params from "../params.js";
import { AesGcmCryptoKey, AesShared, Alg } from "./shared.js";

export async function generateKey(
    algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
        length: 256,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<AesGcmCryptoKey> {
    return await AesShared.generateKey(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        extractable,
        keyUsages
    );
}

export async function importKey(
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesGcmKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesGcmCryptoKey> {
    return await AesShared.importKey(
        format as any,
        keyData as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        extractable,
        keyUsages
    );
}

export const exportKey = AesShared.exportKey;

export async function encrypt(
    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
    keyData: AesGcmCryptoKey,
    plaintext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        keyData,
        plaintext
    );
}

export async function decrypt(
    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
    keyData: AesGcmCryptoKey,
    ciphertext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        keyData,
        ciphertext
    );
}

export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: AesGcmCryptoKey,
    wrapAlgorithm: Omit<params.EnforcedAesGcmParams, "name">
): Promise<ArrayBuffer> {
    return await AesShared.wrapKey(format as any, key, wrappingkey, {
        ...wrapAlgorithm,
        name: Alg.Mode.AES_GCM,
    });
}
export async function unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    wrappedKeyAlgorithm: params.EnforcedImportParams,
    unwrappingKey: AesGcmCryptoKey,
    unwrappingKeyAlgorithm: Omit<params.EnforcedAesGcmParams, "name">,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<CryptoKey> {
    return await AesShared.unwrapKey(
        format,
        wrappedKey,
        wrappedKeyAlgorithm,
        unwrappingKey,
        {
            ...unwrappingKeyAlgorithm,
            name: Alg.Mode.AES_GCM,
        },
        extractable,
        keyUsages
    );
}
