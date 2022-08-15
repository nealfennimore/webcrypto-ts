/**
 * Code related to HKDF
 * @module
 */
import * as params from "../params.js";
import { Alg, HkdfKeyMaterial, KdfShared } from "./shared.js";

export const generateKeyMaterial = (
    format: KeyFormat,
    keyData: BufferSource,
    extractable?: boolean
) =>
    KdfShared.generateKeyMaterial<HkdfKeyMaterial>(
        format,
        keyData,
        Alg.Variant.HKDF,
        extractable
    );

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
