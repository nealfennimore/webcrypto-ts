import { getKeyUsagePairsByAlg, KeyUsagePairs } from "../keyUsages.js";
import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    RsaOaepCryptoKeyPair,
    RsaOaepPrivCryptoKey,
    RsaOaepPubCryptoKey,
    RsaShared,
} from "./shared.js";

export const generateKey = async (
    algorithm: Omit<params.EnforcedRsaHashedKeyGenParams, "name"> = {
        hash: SHA.Variant.SHA_512,
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
) =>
    (await RsaShared.generateKey(
        {
            ...algorithm,
            name: Alg.Variant.RSA_OAEP,
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
): Promise<RsaOaepPrivCryptoKey | RsaOaepPubCryptoKey> =>
    await RsaShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.RSA_OAEP },
        extractable,
        keyUsages
    );

export const exportKey = async (
    format: KeyFormat,
    keyData: RsaOaepPrivCryptoKey | RsaOaepPubCryptoKey
) => RsaShared.exportKey(format, keyData);

export async function encrypt(
    keyData: RsaOaepPubCryptoKey,
    plaintext: BufferSource,
    label?: params.EnforcedRsaOaepParams["label"]
): Promise<ArrayBuffer> {
    const algorithm: params.EnforcedRsaOaepParams = {
        name: Alg.Variant.RSA_OAEP,
        label,
    };
    return await WebCrypto.encrypt(algorithm, keyData, plaintext);
}

export async function decrypt(
    keyData: RsaOaepPrivCryptoKey,
    ciphertext: BufferSource,
    label?: params.EnforcedRsaOaepParams["label"]
): Promise<ArrayBuffer> {
    const algorithm: params.EnforcedRsaOaepParams = {
        name: Alg.Variant.RSA_OAEP,
        label,
    };
    return await WebCrypto.decrypt(algorithm, keyData, ciphertext);
}

export async function wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingkey: RsaOaepPubCryptoKey,
    wrapAlgorithm?: Omit<params.EnforcedRsaOaepParams, "name">
): Promise<ArrayBuffer> {
    const _wrapAlgorithm: params.EnforcedRsaOaepParams = {
        ...wrapAlgorithm,
        name: Alg.Variant.RSA_OAEP,
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
    unwrappingKey: RsaOaepPrivCryptoKey,
    unwrappingKeyAlgorithm: Omit<params.EnforcedRsaOaepParams, "name">,
    extractable: boolean = true,
    keyUsages?: KeyUsagePairs
): Promise<CryptoKey> {
    const _unwrappingKeyAlgorithm: params.EnforcedRsaOaepParams = {
        ...unwrappingKeyAlgorithm,
        name: Alg.Variant.RSA_OAEP,
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
