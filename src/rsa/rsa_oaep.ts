import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg, KeyUsagePairs } from "../keyUsages";
import * as params from "../params";
import { RsaKey, RsaKeyPair, RsaShared } from "./shared";

export namespace RSA_OAEP {
    export const generateKey = async (
        hash: alg.SHA.SecureVariants = alg.SHA.Variant.SHA_512,
        modulusLength: 4096 = 4096,
        publicExponent: Uint8Array = new Uint8Array([0x01, 0x00, 0x01]),
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        (await RsaShared.generateKey(
            {
                name: alg.RSA.Variant.RSA_OAEP,
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
            { name: alg.RSA.Variant.RSA_OAEP, hash },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = RsaShared.exportKey;

    export async function encrypt(
        keyData: RsaKey,
        plaintext: BufferSource,
        label?: BufferSource
    ): Promise<ArrayBuffer> {
        const algorithm: params.EnforcedRsaOaepParams = {
            name: alg.RSA.Variant.RSA_OAEP,
            label,
        };
        return await WebCrypto.encrypt(algorithm, keyData, plaintext);
    }

    export async function decrypt(
        keyData: RsaKey,
        ciphertext: BufferSource,
        label?: BufferSource
    ): Promise<ArrayBuffer> {
        const algorithm: params.EnforcedRsaOaepParams = {
            name: alg.RSA.Variant.RSA_OAEP,
            label,
        };
        return await WebCrypto.decrypt(algorithm, keyData, ciphertext);
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: RsaKey,
        wrapAlgorithm: Omit<params.EnforcedRsaOaepParams, "name">
    ): Promise<ArrayBuffer> {
        const _wrapAlgorithm: params.EnforcedRsaOaepParams = {
            ...wrapAlgorithm,
            name: alg.RSA.Variant.RSA_OAEP,
        };
        return await WebCrypto.wrapKey(
            format as any,
            key,
            wrappingkey,
            _wrapAlgorithm
        );
    }
    export async function unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: RsaKey,
        unwrappingKeyAlgorithm: Omit<params.EnforcedRsaOaepParams, "name">,
        extractable: boolean = true,
        keyUsages?: KeyUsagePairs
    ): Promise<CryptoKey> {
        const _unwrappingKeyAlgorithm: params.EnforcedRsaOaepParams = {
            ...unwrappingKeyAlgorithm,
            name: alg.RSA.Variant.RSA_OAEP,
        };
        return await WebCrypto.unwrapKey(
            format as any,
            wrappedKey,
            unwrappingKey,
            _unwrappingKeyAlgorithm,
            wrappedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(wrappedKeyAlgorithm.name)
        );
    }
}
