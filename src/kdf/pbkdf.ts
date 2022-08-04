import * as alg from "../alg";
import * as params from "../params";
import { KdfShared, Pbkdf2KeyMaterial } from "./shared";

export namespace PBKDF2 {
    const hashIterations: Record<alg.SHA.SecureVariants, number> = {
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
            alg.KDF.Variant.PBKDF2,
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
                name: alg.KDF.Variant.PBKDF2,
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
                name: alg.KDF.Variant.PBKDF2,
                iterations: hashIterations[
                    algorithm.hash
                ] as params.EnforcedPbkdf2Params["iterations"],
            },
            baseKey,
            length
        );
}
