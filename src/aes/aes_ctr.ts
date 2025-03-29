/**
 * Code related to AES_CTR mode
 * @module
 */

import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { getValues } from "../random.js";
import {
    AesCtrCryptoKey,
    AesCtrProxiedCryptoKey,
    AesShared,
    Alg,
} from "./shared.js";

/** @hidden */
export const handler: ProxyHandler<AesCtrCryptoKey> = {
    get(target: AesCtrCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;

            case "encrypt":
                return (
                    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
                    data: BufferSource
                ) => encrypt(algorithm, target, data);

            case "decrypt":
                return (
                    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
                    data: BufferSource
                ) => decrypt(algorithm, target, data);

            case "wrapKey":
                return (
                    format: KeyFormat,
                    key: CryptoKey,
                    wrapAlgorithm: Omit<params.EnforcedAesCtrParams, "name">
                ) => wrapKey(format, key, target, wrapAlgorithm);

            case "unwrapKey":
                return (
                    format: KeyFormat,
                    wrappedKey: BufferSource,
                    wrappedKeyAlgorithm: params.EnforcedImportParams,
                    unwrappingKeyAlgorithm: Omit<
                        params.EnforcedAesCtrParams,
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
 * Generates a counter, with the given length, starting from the count of 1. The nonce is randomized.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/AesCtrParams
 * @example
 * ```ts
 * const counter = await AES_CTR.generateCounter();
 * ```
 */
export async function generateCounter(
    counterLength: number = 8
): Promise<Uint8Array> {
    const nonce = await getValues(16 - counterLength);
    const counter = new Uint8Array(16);
    counter.set([1], 15);
    counter.set(nonce);
    return counter;
}

/**
 * Generate a new AES_CTR key
 * @example
 * ```ts
 * const key = await AES_CTR.generateKey();
 * ```
 */
export async function generateKey(
    algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
        length: 256,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<AesCtrProxiedCryptoKey> {
    const key = await AesShared.generateKey<AesCtrCryptoKey>(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        extractable,
        keyUsages
    );
    return proxy.proxifyKey<AesCtrCryptoKey, AesCtrProxiedCryptoKey>(handler)(
        key
    );
}

/**
 * Import an AES_CTR key from the specified format
 * @example
 * ```ts
 * const key = await AES_CTR.importKey("jwk", jwk, { length: 256 });
 * ```
 */
export async function importKey(
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesCtrKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesCtrProxiedCryptoKey> {
    const importedKey = (await AesShared.importKey(
        format as any,
        key as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        extractable,
        keyUsages
    )) as AesCtrCryptoKey;
    return proxy.proxifyKey<AesCtrCryptoKey, AesCtrProxiedCryptoKey>(handler)(
        importedKey
    );
}

/**
 * Export an AES_CTR key into the specified format
 * @example
 * ```ts
 * const key = await AES_CTR.generateKey();
 * const jwk = await AES_CTR.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const key = await AES_CTR.generateKey();
 * const jwk = await key.exportKey("jwk");
 * ```
 */
export const exportKey = async (format: KeyFormat, key: AesCtrCryptoKey) =>
    AesShared.exportKey(format, key);

/**
 * Encrypt with an AES_CTR key
 * @example
 * ```ts
 * const key = await AES_CTR.generateKey();
 * const message = new TextEncoder().encode("a message");
 * const length = 8;
 * const counter = await AES_CTR.generateCounter(length);
 * const data = await AES_CTR.encrypt({length, counter}, key.self, message);
 * ```
 * @example
 * ```ts
 * const key = await AES_CTR.generateKey();
 * const message = new TextEncoder().encode("a message");
 * const length = 8;
 * const counter = await AES_CTR.generateCounter(length);
 * const data = await key.encrypt({length, counter}, message);
 * ```
 */
export async function encrypt(
    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
    key: AesCtrCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        key,
        data
    );
}

/**
 * Decrypt with an AES_CTR key
 * @example
 * ```ts
 * const data = await AES_CTR.decrypt({length, counter}, key.self, data);
 * ```
 * @example
 * ```ts
 * const data = await key.decrypt({length, counter}, data);
 * ```
 */
export async function decrypt(
    algorithm: Omit<params.EnforcedAesCtrParams, "name">,
    key: AesCtrCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_CTR,
        },
        key,
        data
    );
}

/**
 * Wrap another key with an AES_CTR key
 * @example
 * ```ts
 * const kek = await AES_CTR.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_CTR.generateKey();
 * const length = 8;
 * const counter = await AES_CTR.generateCounter(length);
 * const wrappedKey = await AES_CTR.wrapKey("raw", dek.self, kek.self, {length, counter});
 * ```
 * @example
 * ```ts
 * const kek = await AES_CTR.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_CTR.generateKey();
 * const length = 8;
 * const counter = await AES_CTR.generateCounter(length);
 * const wrappedKey = await kek.wrapKey("raw", dek.self, {length, counter});
 * ```
 */
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

/**
 * Unwrap a wrapped key using the key encryption key
 * @example
 * ```ts
 * const dek = await AES_CTR.unwrapKey("raw", wrappedKey, {name: "AES_CTR"}, kek.self, {length, counter});
 * ```
 * @example
 * ```ts
 * const dek = await kek.unwrapKey("raw", wrappedKey, {name: "AES_CTR"}, {length, counter});
 * ```
 */
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
