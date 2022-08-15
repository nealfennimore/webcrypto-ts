/**
 * Code related to AES_KW
 * @module
 */
import * as params from "../params.js";
import { AesKwCryptoKey, AesShared, Alg } from "./shared.js";

export async function generateKey(
    algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
        length: 256,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<AesKwCryptoKey> {
    return await AesShared.generateKey(
        {
            ...algorithm,
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    );
}

export async function importKey(
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesKwCryptoKey> {
    return await AesShared.importKey(
        format as any,
        keyData as any,
        {
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    );
}

export const exportKey = AesShared.exportKey;

export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: AesKwCryptoKey
): Promise<ArrayBuffer> {
    return await AesShared.wrapKey(format as any, key, wrappingkey, {
        name: Alg.Mode.AES_KW,
    });
}
export async function unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    wrappedKeyAlgorithm: params.EnforcedImportParams,
    unwrappingKey: AesKwCryptoKey,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<CryptoKey> {
    return await AesShared.unwrapKey(
        format,
        wrappedKey,
        wrappedKeyAlgorithm,
        unwrappingKey,
        {
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    );
}
