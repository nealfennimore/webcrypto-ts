import * as alg from "../alg";
import { RsaKey, RsaKeyPair, RsaShared } from "./shared";

export namespace RSASSA_PKCS1_v1_5 {
    export const generateKey = async (
        hash: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        modulusLength: 4096 = 4096,
        publicExponent: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]),
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        (await RsaShared.generateKey(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
                hash,
                modulusLength,
                publicExponent,
            },
            extractable,
            keyUsages
        )) as RsaKeyPair;

    export const importKey = async (
        format: KeyFormat,
        hash: alg.SHA.SecureVariants,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await RsaShared.importKey(
            format,
            { name: alg.RSA.Variant.RSASSA_PKCS1_v1_5, hash },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = RsaShared.exportKey;

    export const sign = async (keyData: RsaKey, data: BufferSource) =>
        await RsaShared.sign(
            {
                name: alg.RSA.Variant.RSASSA_PKCS1_v1_5,
            },
            keyData,
            data
        );

    export const verify = async (
        keyData: RsaKey,
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
