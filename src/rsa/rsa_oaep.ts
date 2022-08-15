import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { getKeyUsagePairsByAlg, KeyUsagePairs } from "../keyUsages.js";
import * as params from "../params.js";
import { RsaOaepCryptoKey, RsaOaepCryptoKeyPair, RsaShared } from "./shared.js";

export namespace RSA_OAEP {
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
                name: alg.RSA.Variant.RSA_OAEP,
            },
            extractable,
            keyUsages
        )) as RsaOaepCryptoKeyPair;

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<RsaOaepCryptoKey> =>
        await RsaShared.importKey(
            format,
            keyData,
            { ...algorithm, name: alg.RSA.Variant.RSA_OAEP },
            extractable,
            keyUsages
        );

    export const exportKey = async (
        format: KeyFormat,
        keyData: RsaOaepCryptoKey
    ) => RsaShared.exportKey(format, keyData);

    export async function encrypt(
        keyData: RsaOaepCryptoKey,
        plaintext: BufferSource,
        label?: params.EnforcedRsaOaepParams["label"]
    ): Promise<ArrayBuffer> {
        const algorithm: params.EnforcedRsaOaepParams = {
            name: alg.RSA.Variant.RSA_OAEP,
            label,
        };
        return await WebCrypto.encrypt(algorithm, keyData, plaintext);
    }

    export async function decrypt(
        keyData: RsaOaepCryptoKey,
        ciphertext: BufferSource,
        label?: params.EnforcedRsaOaepParams["label"]
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
        wrappingkey: RsaOaepCryptoKey,
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
        unwrappingKey: RsaOaepCryptoKey,
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
