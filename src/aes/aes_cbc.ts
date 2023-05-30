/**
 * Code related to AES_CBC mode
 * @module
 */

import * as params from "../params.js";
import * as proxy from "../proxy.js";
import {
    AesCbcCryptoKey,
    AesCbcProxiedCryptoKey,
    AesShared,
    Alg,
} from "./shared.js";

const handler: ProxyHandler<AesCbcCryptoKey> = {
    get(target: AesCbcCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;

            case "encrypt":
                return (
                    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
                    data: BufferSource
                ) => encrypt(algorithm, target, data);

            case "decrypt":
                return (
                    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
                    data: BufferSource
                ) => decrypt(algorithm, target, data);

            case "wrapKey":
                return (
                    format: KeyFormat,
                    key: CryptoKey,
                    wrapAlgorithm: Omit<params.EnforcedAesCbcParams, "name">
                ) => wrapKey(format, key, target, wrapAlgorithm);

            case "unwrapKey":
                return (
                    format: KeyFormat,
                    wrappedKey: BufferSource,
                    wrappedKeyAlgorithm: params.EnforcedImportParams,
                    unwrappingKeyAlgorithm: Omit<
                        params.EnforcedAesCbcParams,
                        "name"
                    >,
                    extractable?: boolean,
                    keyUsages?: KeyUsage[]
                ) =>
                    unwrapKey(
                        format,
                        wrappedKey,
                        wrappedKeyAlgorithm,
                        target,
                        unwrappingKeyAlgorithm,
                        extractable,
                        keyUsages
                    );

            case "exportKey":
                return (format: KeyFormat) => exportKey(format, target);
        }

        return Reflect.get(target, prop);
    },
};

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
): Promise<AesCbcProxiedCryptoKey> {
    const key = await AesShared.generateKey<AesCbcCryptoKey>(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        extractable,
        keyUsages
    );
    return proxy.proxifyKey<AesCbcCryptoKey, AesCbcProxiedCryptoKey>(handler)(
        key
    );
}

/**
 * Import an AES_CBC key
 * @example
 * ```ts
 * const jwk = await AES_CBC.importKey("jwk", jwk, {
 *     length: 256,
 * });
 * ```
 */
export async function importKey(
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesCbcKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesCbcProxiedCryptoKey> {
    const importedKey = (await AesShared.importKey(
        format as any,
        key as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        extractable,
        keyUsages
    )) as AesCbcCryptoKey;
    return proxy.proxifyKey<AesCbcCryptoKey, AesCbcProxiedCryptoKey>(handler)(
        importedKey
    );
}

/**
 * Export an AES_CBC key
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const jwk = await AES_CBC.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const jwk = await key.exportKey("jwk");
 * ```
 */
export const exportKey = async (format: KeyFormat, key: AesCbcCryptoKey) =>
    AesShared.exportKey(format, key);

/**
 * Encrypt payload with an AES_CBC key
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const iv = await IV.generate();
 * const ciphertextBytes = await AES_CBC.encrypt(
 *     { iv },
 *    key.self,
 *    new TextEncoder().encode('message')
 * );
 * ```
 * @example
 * ```ts
 * const key = await AES_CBC.generateKey();
 * const iv = await IV.generate();
 * const ciphertextBytes = await key.encrypt(
 *     { iv },
 *    new TextEncoder().encode('message')
 * );
 * ```
 */
export async function encrypt(
    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
    key: AesCbcCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        key,
        data
    );
}

/**
 * Decrypt data with an AES_CBC key
 * @example
 * ```ts
 * const plaintextBytes = await AES_CBC.decrypt(
 *    { iv },
 *    key.self,
 *    ciphertextBytes
 * );
 * ```
 * @example
 * ```ts
 * const plaintextBytes = await key.decrypt(
 *    { iv },
 *    ciphertextBytes
 * );
 * ```
 */
export async function decrypt(
    algorithm: Omit<params.EnforcedAesCbcParams, "name">,
    key: AesCbcCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CBC,
        },
        key,
        data
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
 * ```ts
 * const kek = await AES_CBC.generateKey({ length: 256 }, true, [
 *    "wrapKey",
 *    "unwrapKey",
 * ]);
 * const dek: AesCbcCryptoKey = await AES_CBC.generateKey({
 *    length: 256,
 * });
 * const iv = await IV.generate();
 * const wrappedKey = await kek.wrapKey("raw", dek.self, {
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
 * const wrappedKey = await AES_CBC.wrapKey("raw", dek.self, kek.self, {
 *     iv,
 * });
 * const unwrappedKey = await AES_CBC.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.AES_CBC },
 *    kek.self,
 *    { iv }
 * );
 * ```
 * @example
 * ```ts
 * const wrappedKey = await AES_CBC.wrapKey("raw", dek.self, kek.self, {
 *     iv,
 * });
 * const unwrappedKey = await kek.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.AES_CBC },
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
