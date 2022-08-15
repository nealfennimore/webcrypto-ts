/**
 * Code related to AES_CBC mode
 * @module
 */

import * as params from "../params.js";
import { AesCbcCryptoKey, AesShared, Alg } from "./shared.js";
/**
 * Generate a new AES_CBC key
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * ```
 */
export async function generateKey(
    algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
        length: 256,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<AesCbcCryptoKey> {
    return await AesShared.generateKey<AesCbcCryptoKey>(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        extractable,
        keyUsages
    );
}

/**
 * Import an AES_CBC key
 * @example
 * ```ts
 * const jwk await AES_CBC.importKey("jwk", jwk, {
 *     length: 256,
 * });
 * ```
 */
export async function importKey(
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesCbcKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesCbcCryptoKey> {
    return await AesShared.importKey(
        format as any,
        keyData as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        extractable,
        keyUsages
    );
}

/**
 * Export an AES_CBC key
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const jwk = await AES_CBC.exportKey("jwk", key);
 * ```
 */
export const exportKey = async (format: KeyFormat, keyData: AesCbcCryptoKey) =>
    AesShared.exportKey(format, keyData);

/**
 * Encrypt a payload with an AES_CBC key
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const iv = await IV.generate();
 * const ciphertextBytes = await AES_CBC.encrypt(
 *     { iv },
 *    key,
 *    new TextEncoder().encode('message')
 * );
 * ```
 */
export async function encrypt(
    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
    keyData: AesCbcCryptoKey,
    plaintext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        keyData,
        plaintext
    );
}

/**
 * Decrypt a ciphertext with an AES_CBC key
 * @example
 * ```ts
 * const plaintextBytes = await AES_CBC.decrypt(
 *    { iv },
 *    key,
 *    ciphertextBytes
 * );
 * ```
 */
export async function decrypt(
    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
    keyData: AesCbcCryptoKey,
    ciphertext: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        keyData,
        ciphertext
    );
}

/**
 * Wrap another key with an AES_CBC key
 * @example
 * ```ts
 * const kek = await AES_CBC.generateKey({ length: 256 }, true, [
 *    "wrapKey",
 *    "unwrapKey",
 * ]);
 * const dek: AesCbcCryptoKey = await AES_CBC.generateKey({
 *    length: 256,
 * });
 * const iv = await IV.generate();
 * const wrappedKey = await AES_CBC.wrapKey("raw", dek, kek, {
 *     iv,
 * });
 * ```
 */
export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: AesCbcCryptoKey,
    wrapAlgorithm: Omit<params.EnforcedAesCbcParams, "name">
): Promise<ArrayBuffer> {
    return await AesShared.wrapKey(format as any, key, wrappingkey, {
        ...wrapAlgorithm,
        name: Alg.Mode.AES_CBC,
    });
}

/**
 * Unwrap a wrapped key using the key encryption key
 * @example
 * ```ts
 * const wrappedKey = await AES_CBC.wrapKey("raw", dek, kek, {
 *     iv,
 * });
 * const unwrappedkey = await AES_CBC.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.AES_CBC },
 *    kek,
 *    { iv }
 * );
 * ```
 */
export async function unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    wrappedKeyAlgorithm: params.EnforcedImportParams,
    unwrappingKey: AesCbcCryptoKey,
    unwrappingKeyAlgorithm: Omit<params.EnforcedAesCbcParams, "name">,
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
            name: Alg.Mode.AES_CBC,
        },
        extractable,
        keyUsages
    );
}
