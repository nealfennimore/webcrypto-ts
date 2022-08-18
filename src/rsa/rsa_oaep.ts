/**
 * Code related to RSA_OAEP
 * @module
 */

import { getKeyUsagePairsByAlg, KeyUsagePairs } from "../key_usages.js";
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

/**
 * Generate a new RSA_OAEP keypair
 * @example
 * ```ts
 * const keyPair = await RSA_OAEP.generateKey();
 * ```
 */
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

/**
 * Import an RSA_OAEP public or private key
 * @example
 * ```ts
 * const key = await RSA_OAEP.importKey("jwk", pubKey, { hash: "SHA-512" }, true, ['encrypt']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<RsaOaepPrivCryptoKey | RsaOaepPubCryptoKey> =>
    await RsaShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.RSA_OAEP },
        extractable,
        keyUsages
    );

/**
 * Export an RSA_OAEP public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await RSA_OAEP.importKey("jwk", keyPair.publicKey);
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: RsaOaepPrivCryptoKey | RsaOaepPubCryptoKey
) => RsaShared.exportKey(format, key);

/**
 * Encrypt with an RSA_OAEP public key
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const data = await RSA_OAEP.encrypt(keyPair.publicKey, message);
 * ```
 */
export async function encrypt(
    key: RsaOaepPubCryptoKey,
    data: BufferSource,
    label?: params.EnforcedRsaOaepParams["label"]
): Promise<ArrayBuffer> {
    const algorithm: params.EnforcedRsaOaepParams = {
        name: Alg.Variant.RSA_OAEP,
        label,
    };
    return await WebCrypto.encrypt(algorithm, key, data);
}

/**
 * Decrypt with an RSA_OAEP private key
 * @example
 * ```ts
 * const data = await RSA_OAEP.decrypt(keyPair.privateKey, data);
 * ```
 */

export async function decrypt(
    key: RsaOaepPrivCryptoKey,
    data: BufferSource,
    label?: params.EnforcedRsaOaepParams["label"]
): Promise<ArrayBuffer> {
    const algorithm: params.EnforcedRsaOaepParams = {
        name: Alg.Variant.RSA_OAEP,
        label,
    };
    return await WebCrypto.decrypt(algorithm, key, data);
}

/**
 * Wrap another key with an RSA_OAEP public key
 * @example
 * ```ts
 * const kek = await RSA_OAEP.generateKey(undefined, true, ['wrapKey', 'unwrapKey']);
 * const dek = await RSA_OAEP.generateKey();
 * const wrappedKey = await RSA_OAEP.wrapKey("raw", dek, kek, {iv});
 * ```
 */
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

/**
 * Unwrap a wrapped key using the key encryption key
 * @example
 * ```ts
 * const wrappedKey = await RSA_OAEP.wrapKey("raw", dek, kek);
 * const unwrappedkey = await RSA_OAEP.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.RSA_OAEP },
 *    kek,
 * );
 * ```
 */
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
