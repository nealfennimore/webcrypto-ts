/**
 * Code related to RSASSA_PKCS1_v1_5
 * @module
 */

import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    RsaShared,
    RsassaPkcs1V15CryptoKeyPair,
    RsassaPkcs1V15PrivCryptoKey,
    RsassaPkcs1V15ProxiedCryptoKeyPair,
    RsassaPkcs1V15ProxiedPrivCryptoKey,
    RsassaPkcs1V15ProxiedPubCryptoKey,
    RsassaPkcs1V15PubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    RsassaPkcs1V15PrivCryptoKey,
    RsassaPkcs1V15PubCryptoKey
> = {
    privHandler: {
        get(target: RsassaPkcs1V15PrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return (data: BufferSource) => sign(target, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: RsassaPkcs1V15PubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return (signature: BufferSource, data: BufferSource) =>
                        verify(target, signature, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new RSASSA_PKCS1_v1_5 keypair
 * @example
 * ```ts
 * const keyPair = await RSASSA_PKCS1_v1_5.generateKey();
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
): Promise<RsassaPkcs1V15ProxiedCryptoKeyPair> => {
    const keyPair = (await RsaShared.generateKey(
        {
            ...algorithm,
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        extractable,
        keyUsages
    )) as RsassaPkcs1V15CryptoKeyPair;
    return proxy.proxifyKeyPair<
        RsassaPkcs1V15CryptoKeyPair,
        RsassaPkcs1V15PrivCryptoKey,
        RsassaPkcs1V15ProxiedPrivCryptoKey,
        RsassaPkcs1V15PubCryptoKey,
        RsassaPkcs1V15ProxiedPubCryptoKey
    >(handlers)(keyPair);
};

/**
 * Generate a new RSASSA_PKCS1_v1_5 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await RSASSA_PKCS1_v1_5.generateKeyPair();
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an RSASSA_PKCS1_v1_5 public or private key
 * @example
 * ```ts
 * const key = await RSASSA_PKCS1_v1_5.importKey("jwk", pubKey, { hash: "SHA-512" }, true, ['verify']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<
    RsassaPkcs1V15ProxiedPubCryptoKey | RsassaPkcs1V15ProxiedPrivCryptoKey
> => {
    const importedKey = await RsaShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.RSASSA_PKCS1_v1_5 },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<
            RsassaPkcs1V15PrivCryptoKey,
            RsassaPkcs1V15ProxiedPrivCryptoKey
        >(handlers.privHandler)(importedKey as RsassaPkcs1V15PrivCryptoKey);
    } else {
        return proxy.proxifyKey<
            RsassaPkcs1V15PubCryptoKey,
            RsassaPkcs1V15ProxiedPubCryptoKey
        >(handlers.pubHandler)(importedKey as RsassaPkcs1V15PubCryptoKey);
    }
};

/**
 * Export an RSASSA_PKCS1_v1_5 public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await RSASSA_PKCS1_v1_5.importKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyJwk = await keyPair.publicKey.importKey("jwk");
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: RsassaPkcs1V15PubCryptoKey | RsassaPkcs1V15PrivCryptoKey
) => RsaShared.exportKey(format, key);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await RSASSA_PKCS1_v1_5.sign(keyPair.privateKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await keyPair.privateKey.sign(message);
 * ```
 */
export const sign = async (
    key: RsassaPkcs1V15PrivCryptoKey,
    data: BufferSource
) =>
    await RsaShared.sign(
        {
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        key,
        data
    );

/**
 * Verify a given signature
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await RSASSA_PKCS1_v1_5.verify(keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify( signature, message);
 * ```
 */
export const verify = async (
    key: RsassaPkcs1V15PubCryptoKey,
    signature: BufferSource,
    data: BufferSource
) =>
    await RsaShared.verify(
        {
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        key,
        signature,
        data
    );
