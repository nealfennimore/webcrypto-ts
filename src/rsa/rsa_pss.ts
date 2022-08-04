import * as alg from "../alg";
import * as params from "../params";
import { RsaKey, RsaKeyPair, RsaShared } from "./shared";

export namespace RSA_PSS {
    export const generateKey = async (
        algorithm: Omit<params.EnforcedRsaHashedKeyGenParams, "name"> = {
            hash: alg.SHA.Variant.SHA_512,
            modulusLength: 4096,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        },
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        (await RsaShared.generateKey(
            {
                ...algorithm,
                name: alg.RSA.Variant.RSA_PSS,
            },
            extractable,
            keyUsages
        )) as RsaKeyPair;

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RsaShared.importKey(
            format,
            keyData,
            { ...algorithm, name: alg.RSA.Variant.RSA_PSS },
            extractable,
            keyUsages
        );

    export const exportKey = RsaShared.exportKey;

    export const sign = async (
        saltLength: number,
        keyData: RsaKey,
        data: BufferSource
    ) =>
        await RsaShared.sign(
            {
                name: alg.RSA.Variant.RSA_PSS,
                saltLength,
            },
            keyData,
            data
        );

    export const verify = async (
        saltLength: number,
        keyData: RsaKey,
        signature: BufferSource,
        data: BufferSource
    ) =>
        await RsaShared.verify(
            {
                name: alg.RSA.Variant.RSA_PSS,
                saltLength,
            },
            keyData,
            signature,
            data
        );
}
