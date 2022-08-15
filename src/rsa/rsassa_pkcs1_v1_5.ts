import * as alg from "../alg.js";
import * as params from "../params.js";
import {
    RsaShared,
    RsassaPkcs1V15CryptoKey,
    RsassaPkcs1V15CryptoKeyPair,
} from "./shared.js";

export namespace RSASSA_PKCS1_v1_5 {
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
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            extractable,
            keyUsages
        )) as RsassaPkcs1V15CryptoKeyPair;

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<RsassaPkcs1V15CryptoKey> =>
        await RsaShared.importKey(
            format,
            keyData,
            { ...algorithm, name: alg.RSA.Variant.RSASSA_PKCS1_v1_5 },
            extractable,
            keyUsages
        );

    export const exportKey = async (
        format: KeyFormat,
        keyData: RsassaPkcs1V15CryptoKey
    ) => RsaShared.exportKey(format, keyData);

    export const sign = async (
        keyData: RsassaPkcs1V15CryptoKey,
        data: BufferSource
    ) =>
        await RsaShared.sign(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            keyData,
            data
        );

    export const verify = async (
        keyData: RsassaPkcs1V15CryptoKey,
        signature: BufferSource,
        data: BufferSource
    ) =>
        await RsaShared.verify(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            keyData,
            signature,
            data
        );
}
