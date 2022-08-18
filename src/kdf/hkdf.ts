/**
 * Code related to HKDF
 * @module
 */
import * as params from "../params.js";
import { Alg, HkdfKeyMaterial, KdfShared } from "./shared.js";

/**
 * Generate key material for deriving
 * @example
 * ```ts
 * const keyMaterial = await HKDF.generateKeyMaterial("raw", new TextEncoder().encode("lots_of_entropy"));
 * ```
 */
export const generateKeyMaterial = (
    format: KeyFormat,
    key: BufferSource,
    extractable?: boolean
) =>
    KdfShared.generateKeyMaterial<HkdfKeyMaterial>(
        format,
        key,
        Alg.Variant.HKDF,
        extractable
    );

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
