/**
 * Code related to PBKDF2
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
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    KdfShared,
    Pbkdf2KeyMaterial,
    Pbkdf2ProxiedKeyMaterial,
} from "./shared.js";

const handler: ProxyHandler<Pbkdf2KeyMaterial> = {
    get(target: Pbkdf2KeyMaterial, prop: string) {
        switch (prop) {
            case "self":
                return target;
            case "deriveKey":
                return (
                    algorithm: Omit<
                        params.EnforcedPbkdf2Params,
                        "name" | "iterations"
                    >,
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
                    algorithm: Omit<params.EnforcedPbkdf2Params, "name">,
                    length: number
                ) => deriveBits(algorithm, target, length);
        }

        return Reflect.get(target, prop);
    },
};

const hashIterations: Record<SHA.Variants, number> = {
    "SHA-1": 1_300_000,
    "SHA-256": 600_000,
    "SHA-384": 600_000,
    "SHA-512": 210_000,
};

/**
 * Generate key material for deriving
 * @example
 * ```ts
 * const keyMaterial = await PBKDF2.generateKeyMaterial("raw", new TextEncoder().encode("could_be_a_little_entropy"));
 * ```
 */
export const generateKeyMaterial = async (
    format: KeyFormat,
    key: BufferSource,
    extractable?: boolean
): Promise<Pbkdf2ProxiedKeyMaterial> => {
    const keyMaterial = await KdfShared.generateKeyMaterial<Pbkdf2KeyMaterial>(
        format,
        key,
        Alg.Variant.PBKDF2,
        extractable
    );

    return proxy.proxifyKey<Pbkdf2KeyMaterial, Pbkdf2ProxiedKeyMaterial>(
        handler
    )(keyMaterial);
};

/**
 * Derive a shared key from PBKDF2 key material
 * @example
 * ```ts
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *     name: Authentication.Alg.Code.HMAC,
 *     hash: SHA.Alg.Variant.SHA_512,
 *     length: 512,
 * };
 * let key = await PBKDF2.deriveKey(
 *     { hash: "SHA512" },
 *     keyMaterial,
 *     hmacParams
 * );
 * ```
 * @example
 * ```ts
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *     name: Authentication.Alg.Code.HMAC,
 *     hash: SHA.Alg.Variant.SHA_512,
 *     length: 512,
 * };
 * const keyMaterial = await PBKDF2.generateKeyMaterial(
 *     "raw",
 *     await Random.getValues(16)
 * );
 * let key = await keyMaterial.deriveKey(
 *     { hash: "SHA512" },
 *     hmacParams
 * );
 * ```
 * @example
 * ```ts
 * const keyMaterial = await PBKDF2.generateKeyMaterial(
 *     "raw",
 *     await Random.getValues(16)
 * );
 * let key = await PBKDF2.deriveKey(
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
 * ```
 */
export const deriveKey = async (
    algorithm: Omit<params.EnforcedPbkdf2Params, "name" | "iterations">,
    baseKey: Pbkdf2KeyMaterial,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<HmacProxiedCryptoKey | AesProxiedCryptoKeys> => {
    const derived = await KdfShared.deriveKey(
        {
            ...algorithm,
            name: Alg.Variant.PBKDF2,
            iterations: hashIterations[
                algorithm.hash
            ] as params.EnforcedPbkdf2Params["iterations"],
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
 * const bits = await PBKDF2.deriveBits(
 *      { hash: "SHA-512" },
 *      keyMaterial,
 *      128
 * );
 * ```
 * @example
 * ```ts
 * const bits = await keyMaterial.deriveBits(
 *      { hash: "SHA-512" },
 *      128
 * );
 * ```
 */
export const deriveBits = (
    algorithm: Omit<params.EnforcedPbkdf2Params, "name" | "iterations">,
    baseKey: Pbkdf2KeyMaterial,
    length: number
) =>
    KdfShared.deriveBits(
        {
            ...algorithm,
            name: Alg.Variant.PBKDF2,
            iterations: hashIterations[
                algorithm.hash
            ] as params.EnforcedPbkdf2Params["iterations"],
        },
        baseKey,
        length
    );
