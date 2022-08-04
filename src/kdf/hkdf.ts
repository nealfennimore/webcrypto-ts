import * as alg from "../alg";
import * as params from "../params";
import { HkdfKeyMaterial, KdfShared } from "./shared";

export namespace HKDF {
    export const generateKeyMaterial = (
        format: KeyFormat,
        keyData: BufferSource,
        extractable?: boolean
    ) =>
        KdfShared.generateKeyMaterial<HkdfKeyMaterial>(
            format,
            keyData,
            alg.KDF.Variant.HKDF,
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
                name: alg.KDF.Variant.HKDF,
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
                name: alg.KDF.Variant.HKDF,
            },
            baseKey,
            length
        );
}
