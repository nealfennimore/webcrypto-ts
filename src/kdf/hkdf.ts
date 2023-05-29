/**
 * Code related to HKDF
 * @module
 */
import type { AesCryptoKeys } from "../aes/index.js";
import { HmacCryptoKey } from "../hmac/index.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg, HkdfKeyMaterial, KdfShared } from "./shared.js";

export interface HkdfProxiedKeyMaterial
    extends proxy.ProxiedCryptoKey<HkdfKeyMaterial> {
    deriveKey(
        algorithm: Omit<params.EnforcedHkdfParams, "name">,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesCryptoKeys | HmacCryptoKey>;

    deriveBits(
        algorithm: Omit<params.EnforcedHkdfParams, "name">,
        length: number
    ): Promise<ArrayBuffer>;
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

const handler: ProxyHandler<HkdfKeyMaterial> = {
    get(target: HkdfKeyMaterial, prop: string) {
        switch (prop) {
            case "self":
                return target;
            case "deriveKey":
                return (
                    algorithm: Omit<params.EnforcedHkdfParams, "name">,
                    derivedKeyType:
                        | params.EnforcedAesKeyGenParams
                        | params.EnforcedHmacKeyGenParams,
                    extractable?: boolean,
                    keyUsages?: KeyUsage[]
                ) =>
                    deriveKey(
                        algorithm,
                        target,
                        derivedKeyType,
                        extractable,
                        keyUsages
                    );
            case "deriveBits":
                return (
                    algorithm: Omit<params.EnforcedHkdfParams, "name">,
                    length: number
                ) => deriveBits(algorithm, target, length);
        }

        return Reflect.get(target, prop);
    },
};

/**
 * Generate key material for deriving
 * @example
 * ```ts
 * const keyMaterial = await HKDF.generateKeyMaterial("raw", new TextEncoder().encode("lots_of_entropy"));
 * ```
 */
export const generateKeyMaterial = async (
    format: KeyFormat,
    key: BufferSource,
    extractable?: boolean
): Promise<HkdfProxiedKeyMaterial> => {
    const keyMaterial = await KdfShared.generateKeyMaterial<HkdfKeyMaterial>(
        format,
        key,
        Alg.Variant.HKDF,
        extractable
    );

    return proxy.proxifyKey<HkdfKeyMaterial, HkdfProxiedKeyMaterial>(handler)(
        keyMaterial
    );
};

/**
 * Derive a shared key from HKDF key material
 * @example
 * ```ts
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * const salt = await Random.Salt.generate();
 * const info = await Random.getValues(6);
 * let key = await HKDF.deriveKey(
 *      { salt, info, hash: "SHA-512" },
 *      keyMaterial,
 *      hmacParams
 * );
 * @example
 * ```ts
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * const salt = await Random.Salt.generate();
 * const info = await Random.getValues(6);
 * let key = await keyMaterial.deriveKey(
 *      { salt, info, hash: "SHA-512" },
 *      hmacParams
 * );
 * ```
 */
export const deriveKey = (
    algorithm: Omit<params.EnforcedHkdfParams, "name">,
    baseKey: HkdfKeyMaterial,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
) =>
    KdfShared.deriveKey(
        {
            ...algorithm,
            name: Alg.Variant.HKDF,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages
    );

/**
 * Derive a number bits with a given key material
 * @example
 * ```ts
 * const salt = await Random.Salt.generate();
 * const info = await Random.getValues(6);
 * const bits = await HKDF.deriveBits(
 *      { salt, info, hash: "SHA-512" },
 *      keyMaterial,
 *      128
 * );
 * ```
 * @example
 * ```ts
 * const salt = await Random.Salt.generate();
 * const info = await Random.getValues(6);
 * const bits = await keyMaterial.deriveBits(
 *      { salt, info, hash: "SHA-512" },
 *      128
 * );
 * ```
 */
export const deriveBits = (
    algorithm: Omit<params.EnforcedHkdfParams, "name">,
    baseKey: HkdfKeyMaterial,
    length: number
) =>
    KdfShared.deriveBits(
        {
            ...algorithm,
            name: Alg.Variant.HKDF,
        },
        baseKey,
        length
    );
