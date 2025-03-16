/**
 * Code related to HKDF
 * @module
 */
import { handler as AesCbcHandler } from "../aes/aes_cbc.js";
import { handler as AesCtrHandler } from "../aes/aes_ctr.js";
import { handler as AesGcmHandler } from "../aes/aes_gcm.js";
import { handler as AesKwHandler } from "../aes/aes_kw.js";
import {
    Alg as AesAlg,
    AesCbcCryptoKey,
    AesCbcProxiedCryptoKey,
    AesCtrCryptoKey,
    AesCtrProxiedCryptoKey,
    AesGcmCryptoKey,
    AesGcmProxiedCryptoKey,
    AesKwCryptoKey,
    AesKwProxiedCryptoKey,
    AesProxiedCryptoKeys,
} from "../aes/shared.js";
import {
    Alg as HmacAlg,
    HmacCryptoKey,
    HmacProxiedCryptoKey,
    handler as hmacHandler,
} from "../hmac/index.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import {
    Alg,
    HkdfKeyMaterial,
    HkdfProxiedKeyMaterial,
    KdfShared,
} from "./shared.js";

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
 * ```
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
 * @example
 * ```ts
 * const keyMaterial = await HKDF.generateKeyMaterial(
 *     "raw",
 *     await Random.getValues(16)
 * );
 * let key = await HKDF.deriveKey(
 *     {
 *         hash: "SHA-256",
 *         salt,
 *     },
 *     keyMaterial.self,
 *     {
 *         name: "AES-GCM",
 *         length: 256,
 *     }
 * );
 * ```
 * @example
 * ```ts
 * const key = await keyMaterial.deriveKey(
 *     {
 *         hash: "SHA-256",
 *         salt,
 *     },
 *     {
 *         name: "AES-GCM",
 *         length: 256,
 *     }
 * );
 */
export const deriveKey = async (
    algorithm: Omit<params.EnforcedHkdfParams, "name">,
    baseKey: HkdfKeyMaterial,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<HmacProxiedCryptoKey | AesProxiedCryptoKeys> => {
    const derived = await KdfShared.deriveKey(
        {
            ...algorithm,
            name: Alg.Variant.HKDF,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages
    );

    switch (derivedKeyType.name) {
        case HmacAlg.Code.HMAC:
            return proxy.proxifyKey<HmacCryptoKey, HmacProxiedCryptoKey>(
                hmacHandler
            )(derived as HmacCryptoKey);
        case AesAlg.Mode.AES_CBC:
            return proxy.proxifyKey<AesCbcCryptoKey, AesCbcProxiedCryptoKey>(
                AesCbcHandler
            )(derived as AesCbcCryptoKey);
        case AesAlg.Mode.AES_CTR:
            return proxy.proxifyKey<AesCtrCryptoKey, AesCtrProxiedCryptoKey>(
                AesCtrHandler
            )(derived as AesCtrCryptoKey);
        case AesAlg.Mode.AES_GCM:
            return proxy.proxifyKey<AesGcmCryptoKey, AesGcmProxiedCryptoKey>(
                AesGcmHandler
            )(derived as AesGcmCryptoKey);
        case AesAlg.Mode.AES_KW:
            return proxy.proxifyKey<AesKwCryptoKey, AesKwProxiedCryptoKey>(
                AesKwHandler
            )(derived as AesKwCryptoKey);
    }

    throw new Error("Invalid alg");
};

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
