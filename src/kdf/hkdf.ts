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
        baseKey: HkdfKeyMaterial,
        salt: BufferSource,
        info: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        KdfShared.deriveKey(
            {
                name: alg.KDF.Variant.HKDF,
                hash: hashAlgorithm,
                salt,
                info,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages
        );

    export const deriveBits = (
        baseKey: HkdfKeyMaterial,
        salt: BufferSource,
        info: BufferSource,
        hashAlgorithm: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        length: number
    ) =>
        KdfShared.deriveBits(
            {
                name: alg.KDF.Variant.HKDF,
                hash: hashAlgorithm,
                salt,
                info,
            },
            baseKey,
            length
        );
}
