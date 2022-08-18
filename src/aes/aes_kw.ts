/**
 * Code related to AES_KW mode
 * @module
 */
import * as params from "../params.js";
import { AesKwCryptoKey, AesShared, Alg } from "./shared.js";

/**
 * Generate a new AES_KW key
 * @example
 * ```ts
 * const key = await AES_KW.generateKey();
 * ```
 */
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

/**
 * Import an AES_KW key from the specified format
 * @example
 * ```ts
 * const key = await AES_KW.importKey("jwk", jwk);
 * ```
 */
export async function importKey(
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesKwCryptoKey> {
    return await AesShared.importKey(
        format as any,
        key as any,
        {
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    );
}

/**
 * Export an AES_KW key into the specified format
 * @example
 * ```ts
 * const jwk = await AES_KW.exportKey("jwk", key);
 * ```
 */
export const exportKey = async (format: KeyFormat, key: AesKwCryptoKey) =>
    AesShared.exportKey(format, key);

/**
 * Wrap another key with an AES_KW key
 * @example
 * ```ts
 * const kek = await AES_KW.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_GCM.generateKey();
 * const wrappedKey = await AES_GCM.wrapKey("raw", dek, kek);
 * ```
 */
export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: AesKwCryptoKey
): Promise<ArrayBuffer> {
    return await AesShared.wrapKey(format as any, key, wrappingkey, {
        name: Alg.Mode.AES_KW,
    });
}

/**
 * Unwrap a wrapped key using the key encryption key
 * @example
 * ```ts
 * const dek = await AES_GCM.unwrapKey("raw", wrappedKey, {name: "AES_GCM"}, kek);
 * ```
 */
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
