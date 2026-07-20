/**
 * Code related to KMAC128. Requires Node.js 24.8.0 or higher.
 * @module
 */
import { ExtendedKeyFormat, ExtendedKeyUsage } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg, KmacCryptoKey, KmacProxiedCryptoKey, KmacShared } from "./shared.js";

/** @hidden */
export const handler: ProxyHandler<KmacCryptoKey> = {
    get(target: KmacCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;
            case "sign":
                return (
                    algorithm: Omit<params.EnforcedKmacParams, "name">,
                    data: BufferSource
                ) => sign(algorithm, target, data);
            case "verify":
                return (
                    algorithm: Omit<params.EnforcedKmacParams, "name">,
                    signature: BufferSource,
                    data: BufferSource
                ) => verify(algorithm, target, signature, data);
            case "exportKey":
                return (format: ExtendedKeyFormat) =>
                    exportKey(format, target);
        }

        return Reflect.get(target, prop);
    },
};

/**
 * Generate a new KMAC128 key
 * @example
 * ```ts
 * const key = await KMAC128.generateKey();
 * ```
 * @example
 * ```ts
 * const key = await KMAC128.generateKey({ length: 256 });
 * ```
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedKmacKeyGenParams, "name"> = {},
    extractable: boolean = true,
    keyUsages?: ExtendedKeyUsage[]
): Promise<KmacProxiedCryptoKey> => {
    const key = await KmacShared.generateKey(
        { ...algorithm, name: Alg.Code.KMAC128 },
        extractable,
        keyUsages
    );
    return proxy.proxifyKey<KmacCryptoKey, KmacProxiedCryptoKey>(handler)(key);
};

/**
 * Import a KMAC128 key from the specified format
 * @example
 * ```ts
 * const key = await KMAC128.importKey("jwk", jwk);
 * ```
 * @example
 * ```ts
 * const key = await KMAC128.importKey("raw-secret", bytes);
 * ```
 */
export const importKey = async (
    format: ExtendedKeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedKmacImportParams, "name"> = {},
    extractable: boolean = true,
    keyUsages?: ExtendedKeyUsage[]
): Promise<KmacProxiedCryptoKey> => {
    const importedKey = await KmacShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Code.KMAC128 },
        extractable,
        keyUsages
    );
    return proxy.proxifyKey<KmacCryptoKey, KmacProxiedCryptoKey>(handler)(
        importedKey
    );
};

/**
 * Export a KMAC128 key into the specified format
 * @example
 * ```ts
 * const jwk = await KMAC128.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const jwk = await key.exportKey("jwk");
 * ```
 */
export async function exportKey(
    format: ExtendedKeyFormat,
    key: KmacCryptoKey
): Promise<JsonWebKey | ArrayBuffer> {
    return await KmacShared.exportKey(format, key);
}

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await KMAC128.sign({ outputLength: 256 }, key.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await key.sign({ outputLength: 256 }, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const customization = new TextEncoder().encode("my-protocol");
 * const signature = await key.sign({ outputLength: 256, customization }, message);
 * ```
 */
export async function sign(
    algorithm: Omit<params.EnforcedKmacParams, "name">,
    key: KmacCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await KmacShared.sign(
        { ...algorithm, name: Alg.Code.KMAC128 },
        key,
        data
    );
}

/**
 * Verify a given signature
 * @example
 * ```ts
 * const isVerified = await KMAC128.verify({ outputLength: 256 }, key.self, signature, message);
 * ```
 * @example
 * ```ts
 * const isVerified = await key.verify({ outputLength: 256 }, signature, message);
 * ```
 */
export async function verify(
    algorithm: Omit<params.EnforcedKmacParams, "name">,
    key: KmacCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await KmacShared.verify(
        { ...algorithm, name: Alg.Code.KMAC128 },
        key,
        signature,
        data
    );
}
