/**
 * Code related to RSA_OAEP
 * @module
 */

import { getKeyUsagePairsByAlg, KeyUsagePairs } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg as SHA } from "../sha/shared.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    RsaOaepCryptoKeyPair,
    RsaOaepPrivCryptoKey,
    RsaOaepProxiedCryptoKeyPair,
    RsaOaepProxiedPrivCryptoKey,
    RsaOaepProxiedPubCryptoKey,
    RsaOaepPubCryptoKey,
    RsaShared,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    RsaOaepPrivCryptoKey,
    RsaOaepPubCryptoKey
> = {
    privHandler: {
        get(target: RsaOaepPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "decrypt":
                    return (
                        algorithm: Omit<params.EnforcedRsaOaepParams, "name">,
                        data: BufferSource
                    ) => decrypt(algorithm, target, data);
                case "unwrapKey":
                    return (
                        format: KeyFormat,
                        wrappedKey: BufferSource,
                        wrappedKeyAlgorithm: params.EnforcedImportParams,
                        unwrappingKeyAlgorithm: Omit<
                            params.EnforcedRsaOaepParams,
                            "name"
                        >,
                        extractable?: boolean,
                        keyUsages?: KeyUsagePairs
                    ) =>
                        unwrapKey(
                            format,
                            wrappedKey,
                            wrappedKeyAlgorithm,
                            target,
                            unwrappingKeyAlgorithm,
                            extractable,
                            keyUsages
                        );
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: RsaOaepPubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "encrypt":
                    return (
                        algorithm: Omit<params.EnforcedRsaOaepParams, "name">,
                        data: BufferSource
                    ) => encrypt(algorithm, target, data);
                case "wrapKey":
                    return (
                        format: KeyFormat,
                        key: CryptoKey,
                        wrapAlgorithm?: Omit<
                            params.EnforcedRsaOaepParams,
                            "name"
                        >
                    ) => wrapKey(format, key, target, wrapAlgorithm);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

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
): Promise<RsaOaepProxiedCryptoKeyPair> => {
    const keyPair = (await RsaShared.generateKey(
        {
            ...algorithm,
            name: Alg.Variant.RSA_OAEP,
        },
        extractable,
        keyUsages
    )) as RsaOaepCryptoKeyPair;

    return proxy.proxifyKeyPair<
        RsaOaepCryptoKeyPair,
        RsaOaepPrivCryptoKey,
        RsaOaepProxiedPrivCryptoKey,
        RsaOaepPubCryptoKey,
        RsaOaepProxiedPubCryptoKey
    >(handlers)(keyPair);
};

/**
 * Generate a new RSA_OAEP keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await RSA_OAEP.generateKeyPair();
 * ```
 */
export const generateKeyPair = generateKey;

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
): Promise<RsaOaepProxiedPrivCryptoKey | RsaOaepProxiedPubCryptoKey> => {
    const importedKey = await RsaShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.RSA_OAEP },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<
            RsaOaepPrivCryptoKey,
            RsaOaepProxiedPrivCryptoKey
        >(handlers.privHandler)(importedKey as RsaOaepPrivCryptoKey);
    } else {
        return proxy.proxifyKey<
            RsaOaepPubCryptoKey,
            RsaOaepProxiedPubCryptoKey
        >(handlers.pubHandler)(importedKey as RsaOaepPubCryptoKey);
    }
};

/**
 * Export an RSA_OAEP public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await RSA_OAEP.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyJwk = await keyPair.publicKey.exportKey("jwk");
 * const privKeyJwk = await keyPair.privateKey.exportKey("jwk");
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
 * const data = await RSA_OAEP.encrypt({label}, keyPair.publicKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const data = await keyPair.publicKey.encrypt({label}, message);
 * ```
 */
export async function encrypt(
    algorithm: Omit<params.EnforcedRsaOaepParams, "name"> = {},
    key: RsaOaepPubCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.encrypt(
        {
            ...algorithm,
            name: Alg.Variant.RSA_OAEP,
        },
        key,
        data
    );
}

/**
 * Decrypt with an RSA_OAEP private key
 * @example
 * ```ts
 * const data = await RSA_OAEP.decrypt({label}, keyPair.privateKey.self, data);
 * ```
 * @example
 * ```ts
 * const data = await keyPair.privateKey.decrypt({label}, data);
 * ```
 */
export async function decrypt(
    algorithm: Omit<params.EnforcedRsaOaepParams, "name"> = {},
    key: RsaOaepPrivCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.decrypt(
        {
            ...algorithm,
            name: Alg.Variant.RSA_OAEP,
        },
        key,
        data
    );
}

/**
 * Wrap another key with an RSA_OAEP public key
 * @example
 * ```ts
 * const kek = await RSA_OAEP.generateKey(undefined, true, ['wrapKey', 'unwrapKey']);
 * const dek = await RSA_OAEP.generateKey();
 * const label = await Random.getValues(8);
 * const wrappedKey = await RSA_OAEP.wrapKey("raw", dek.self, kek.self, {label});
 * ```
 * @example
 * ```ts
 * const kek = await RSA_OAEP.generateKey(undefined, true, ['wrapKey', 'unwrapKey']);
 * const dek = await RSA_OAEP.generateKey();
 * const label = await Random.getValues(8);
 * const wrappedKey = await kek.wrapKey("raw", dek.self, {label});
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
 * const wrappedKey = await RSA_OAEP.wrapKey("raw", dek.self, kek.self);
 * const unwrappedKey = await RSA_OAEP.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.RSA_OAEP },
 *    kek.self,
 * );
 * ```
 * ```ts
 * const wrappedKey = await kek.wrapKey("raw", dek.self);
 * const unwrappedKey = await kek.unwrapKey(
 *    "raw",
 *    wrappedKey,
 *    { name: Alg.Mode.RSA_OAEP },
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
