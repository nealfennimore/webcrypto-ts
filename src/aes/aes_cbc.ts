/**
 * Code related to AES_CBC
 * @module
 */

import * as params from "../params.js";
import { AesCbcCryptoKey, AesShared, Alg } from "./shared.js";
/**
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * ```
 * @category key generation
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
 * @example
 * ```ts
 * const jwk await AES_CBC.importKey("jwk", jwk, {
 *     length: 256,
 * });
 * ```
 * @category key generation
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
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const jwk = await AES_CBC.exportKey("jwk", key);
 * ```
 * @category key generation
 */
export const exportKey = AesShared.exportKey;

/**
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
 * @category encryption
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
 * @example
 * ```ts
 * const plaintextBytes = await AES_CBC.decrypt(
 *    { iv },
 *    key,
 *    ciphertextBytes
 * );
 * ```
 * @category encryption
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
 * @category key wrapping
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
 * @category key wrapping
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
