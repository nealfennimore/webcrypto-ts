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
        baseKey: Pbkdf2KeyMaterial,
        salt: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        KdfShared.deriveKey(
            {
                name: alg.KDF.Variant.PBKDF2,
                hash: hashAlgorithm,
                salt,
                iterations: hashIterations[hashAlgorithm] as any,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages
        );

    export const deriveBits = (
        baseKey: Pbkdf2KeyMaterial,
        salt: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        length: number
    ) =>
        KdfShared.deriveBits(
            {
                name: alg.KDF.Variant.PBKDF2,
                hash: hashAlgorithm,
                salt,
                iterations: hashIterations[hashAlgorithm] as any,
            },
            baseKey,
            length
        );
}
