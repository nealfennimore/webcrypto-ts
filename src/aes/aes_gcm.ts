/**
 * Code related to AES_GCM mode
 * @module
 */
import * as params from "../params.js";
import { AesGcmCryptoKey, AesShared, Alg } from "./shared.js";

/**
 * Generate a new AES_GCM key
 * @example
 * ```ts
 * const key = await AES_GCM.generateKey();
 * ```
 */
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

/**
 * Import an AES_GCM key from the specified format
 * @example
 * ```ts
 * const key = await AES_GCM.importKey("jwk", jwk, { length: 256 });
 * ```
 */
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

/**
 * Export an AES_GCM key into the specified format
 * @example
 * ```ts
 * const jwk = await AES_GCM.exportKey("jwk", key);
 * ```
 */
export const exportKey = async (format: KeyFormat, keyData: AesGcmCryptoKey) =>
    AesShared.exportKey(format, keyData);

/**
 * Encrypt with an AES_GCM key
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const key = await AES_GCM.generateKey();
 * const message = new TextEncoder().encode("a message");
 * const ciphertext = await AES_GCM.encrypt({iv}, key, message);
 * ```
 */
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

/**
 * Decrypt with an AES_GCM key
 * @example
 * ```ts
 * const plaintext = await AES_GCM.decrypt({iv}, key, ciphertext);
 * ```
 */
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

/**
 * Wrap another key with an AES_GCM key
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const kek = await AES_GCM.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_GCM.generateKey();
 * const wrappedKey = await AES_GCM.wrapKey("raw", dek, kek, {iv});
 * ```
 */
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

/**
 * Unwrap a wrapped key using the key encryption key
 * @example
 * ```ts
 * const dek = await AES_GCM.unwrapKey("raw", wrappedKey, {name: "AES_GCM"}, kek, {iv});
 * ```
 */
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
