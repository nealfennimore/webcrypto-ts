/**
 * Code related to PBKDF2
 * @module
 */
import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import { Alg, KdfShared, Pbkdf2KeyMaterial } from "./shared.js";

const hashIterations: Record<SHA.SecureVariants, number> = {
    "SHA-256": 310_000,
    "SHA-384": 310_000,
    "SHA-512": 120_000,
};

/**
 * Generate key material for deriving
 * @example
 * ```ts
 * const keyMaterial = await PBKDF2.generateKeyMaterial("raw", new TextEncoder().encode("could_be_a_little_entropy"));
 * ```
 */
export const generateKeyMaterial = (
    format: KeyFormat,
    keyData: BufferSource,
    extractable?: boolean
) =>
    KdfShared.generateKeyMaterial<Pbkdf2KeyMaterial>(
        format,
        keyData,
        Alg.Variant.PBKDF2,
        extractable
    );

/**
 * Derive a shared key from PBKDF2 key material
 * @example
 * ```ts
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * let key = await PBKDF2.deriveKey(
 *      { hash: "SHA-512" },
 *      keyMaterial,
 *      hmacParams
 * );
 * ```
 */
export const deriveKey = (
    algorithm: Omit<params.EnforcedPbkdf2Params, "name" | "iterations">,
    baseKey: Pbkdf2KeyMaterial,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
) =>
    KdfShared.deriveKey(
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
