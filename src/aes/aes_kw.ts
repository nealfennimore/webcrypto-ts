/**
 * Code related to AES_KW mode
 * @module
 */
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { AesKwCryptoKey, AesShared, Alg } from "./shared.js";

export interface AesKwProxiedCryptoKey
    extends proxy.ProxiedCryptoKey<AesKwCryptoKey> {
    wrapKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer>;

    unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

const handler: ProxyHandler<AesKwCryptoKey> = {
    get(target: AesKwCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;

            case "wrapKey":
                return (format: KeyFormat, key: CryptoKey) =>
                    wrapKey(format, key, target);
            case "unwrapKey":
                return (
                    format: KeyFormat,
                    wrappedKey: BufferSource,
                    wrappedKeyAlgorithm: params.EnforcedImportParams,
                    extractable?: boolean,
                    keyUsages?: KeyUsage[]
                ) =>
                    unwrapKey(
                        format,
                        wrappedKey,
                        wrappedKeyAlgorithm,
                        target,
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
): Promise<AesKwProxiedCryptoKey> {
    const key = (await AesShared.generateKey(
        {
            ...algorithm,
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    )) as AesKwCryptoKey;
    return proxy.proxifyKey<AesKwCryptoKey, AesKwProxiedCryptoKey>(handler)(
        key
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
): Promise<AesKwProxiedCryptoKey> {
    const importedKey = (await AesShared.importKey(
        format as any,
        key as any,
        {
            name: Alg.Mode.AES_KW,
        },
        extractable,
        keyUsages
    )) as AesKwCryptoKey;
    return proxy.proxifyKey<AesKwCryptoKey, AesKwProxiedCryptoKey>(handler)(
        importedKey
    );
}

/**
 * Export an AES_KW key into the specified format
 * @example
 * ```ts
 * const jwk = await AES_KW.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const jwk = await key.exportKey("jwk");
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
 * const wrappedKey = await AES_KW.wrapKey("raw", dek.self, kek.self);
 * ```
 * @example
 * ```ts
 * const kek = await AES_KW.generateKey({length: 256}, true, ['wrapKey', 'unwrapKey']);
 * const dek = await AES_GCM.generateKey();
 * const wrappedKey = await kek.wrapKey("raw", dek.self);
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
 * const dek = await AES_KW.unwrapKey("raw", wrappedKey, {name: "AES_GCM"}, kek.self);
 * ```
 * @example
 * ```ts
 * const dek = await kek.unwrapKey("raw", wrappedKey, {name: "AES_GCM"});
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
