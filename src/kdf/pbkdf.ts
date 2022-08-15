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
