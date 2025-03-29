/**
 * Code related to AES_GCM mode
 * @module
 */
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import {
    AesGcmCryptoKey,
    AesGcmProxiedCryptoKey,
    AesShared,
    Alg,
} from "./shared.js";

/** @hidden */
export const handler: ProxyHandler<AesGcmCryptoKey> = {
    get(target: AesGcmCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;

            case "encrypt":
                return (
                    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
                    data: BufferSource
                ) => encrypt(algorithm, target, data);

            case "decrypt":
                return (
                    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
                    data: BufferSource
                ) => decrypt(algorithm, target, data);

            case "wrapKey":
                return (
                    format: KeyFormat,
                    key: CryptoKey,
                    wrapAlgorithm: Omit<params.EnforcedAesGcmParams, "name">
                ) => wrapKey(format, key, target, wrapAlgorithm);

            case "unwrapKey":
                return (
                    format: KeyFormat,
                    wrappedKey: BufferSource,
                    wrappedKeyAlgorithm: params.EnforcedImportParams,
                    unwrappingKeyAlgorithm: Omit<
                        params.EnforcedAesGcmParams,
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
): Promise<AesGcmProxiedCryptoKey> {
    const key = await AesShared.generateKey<AesGcmCryptoKey>(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        extractable,
        keyUsages
    );
    return proxy.proxifyKey<AesGcmCryptoKey, AesGcmProxiedCryptoKey>(handler)(
        key
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
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.AesGcmKeyAlgorithm, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<AesGcmProxiedCryptoKey> {
    const importedKey = (await AesShared.importKey(
        format as any,
        key as any,
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        extractable,
        keyUsages
    )) as AesGcmCryptoKey;
    return proxy.proxifyKey<AesGcmCryptoKey, AesGcmProxiedCryptoKey>(handler)(
        importedKey
    );
}

/**
 * Export an AES_GCM key into the specified format
 * @example
 * ```ts
 * const key = await AES_GCM.generateKey();
 * const jwk = await AES_GCM.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const key = await AES_GCM.generateKey();
 * const jwk = await key.exportKey("jwk");
 * ```
 */
export const exportKey = async (format: KeyFormat, key: AesGcmCryptoKey) =>
    AesShared.exportKey(format, key);

/**
 * Encrypt with an AES_GCM key
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const key = await AES_GCM.generateKey();
 * const message = new TextEncoder().encode("a message");
 * const data = await AES_GCM.encrypt({iv}, key.self, message);
 * ```
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const key = await AES_GCM.generateKey();
 * const message = new TextEncoder().encode("a message");
 * const data = await key.encrypt({iv}, message);
 * ```
 */
export async function encrypt(
    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
    key: AesGcmCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.encrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        key,
        data
    );
}

/**
 * Decrypt with an AES_GCM key
 * @example
 * ```ts
 * const key = await AES_GCM.generateKey();
 * const data = await AES_GCM.decrypt({iv}, key.self, data);
 * ```
 * @example
 * ```ts
 * const key = await AES_GCM.generateKey();
 * const data = await key.decrypt({iv}, data);
 * ```
 */
export async function decrypt(
    algorithm: Omit<params.EnforcedAesGcmParams, "name">,
    key: AesGcmCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await AesShared.decrypt(
        {
            ...algorithm,
            name: Alg.Mode.AES_GCM,
        },
        key,
        data
    );
}

/**
 * Wrap another key with an AES_GCM key
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const kek = await AES_GCM.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_GCM.generateKey();
 * const wrappedKey = await AES_GCM.wrapKey("raw", dek.self, kek.self, {iv});
 * ```
 * @example
 * ```ts
 * const iv = await Random.IV.generate();
 * const kek = await AES_GCM.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_GCM.generateKey();
 * const wrappedKey = await kek.wrapKey("raw", dek.self, {iv});
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
 * @example
 * ```ts
 * const dek = await kek.unwrapKey("raw", wrappedKey, {name: "AES_GCM"}, {iv});
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
