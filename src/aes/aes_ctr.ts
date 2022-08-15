/**
 * Code related to AES_CTR
 * @module
 */

import * as params from "../params.js";
import { getValues } from "../random.js";
import { AesCtrCryptoKey, AesShared, Alg } from "./shared.js";

export async function generateCounter(
    counterLength: number = 8
): Promise<Uint8Array> {
    const nonce = await getValues(16 - counterLength);
    const counter = new Uint8Array(16);
    counter.set([1], 15);
    counter.set(nonce);
    return counter;
}
export async function generateKey(
    algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
        length: 256,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<AesCtrCryptoKey> {
    return await AesShared.generateKey(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        extractable,
        keyUsages
    );
}

export async function importKey(
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesCtrKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesCtrCryptoKey> {
    return await AesShared.importKey(
        format as any,
        keyData as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        extractable,
        keyUsages
    );
}

export const exportKey = AesShared.exportKey;

export async function encrypt(
    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
    keyData: AesCtrCryptoKey,
    plaintext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        keyData,
        plaintext
    );
}

export async function decrypt(
    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
    keyData: AesCtrCryptoKey,
    ciphertext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        keyData,
        ciphertext
    );
}

export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: AesCtrCryptoKey,
    wrapAlgorithm: Omit<params.EnforcedAesCtrParams, "name">
): Promise<ArrayBuffer> {
    return await AesShared.wrapKey(format as any, key, wrappingkey, {
        ...wrapAlgorithm,
        name: Alg.Mode.AES_CTR,
    });
}
export async function unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    wrappedKeyAlgorithm: params.EnforcedImportParams,
    unwrappingKey: AesCtrCryptoKey,
    unwrappingKeyAlgorithm: Omit<params.EnforcedAesCtrParams, "name">,
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
            name: Alg.Mode.AES_CTR,
        },
        extractable,
        keyUsages
    );
}
