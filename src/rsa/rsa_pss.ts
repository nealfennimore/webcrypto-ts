/**
 * Code related to RSA_PSS
 * @module
 */

import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    RsaPssCryptoKeyPair,
    RsaPssPrivCryptoKey,
    RsaPssProxiedCryptoKeyPair,
    RsaPssProxiedPrivCryptoKey,
    RsaPssProxiedPubCryptoKey,
    RsaPssPubCryptoKey,
    RsaShared,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    RsaPssPrivCryptoKey,
    RsaPssPubCryptoKey
> = {
    privHandler: {
        get(target: RsaPssPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return (saltLength: number, data: BufferSource) =>
                        sign(saltLength, target, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: RsaPssPubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return (
                        saltLength: number,
                        signature: BufferSource,
                        data: BufferSource
                    ) => verify(saltLength, target, signature, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new RSA_PSS keypair
 * @example
 * ```ts
 * const keyPair = await RSA_PSS.generateKey();
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
): Promise<RsaPssProxiedCryptoKeyPair> => {
    const keyPair = (await RsaShared.generateKey(
        {
            ...algorithm,
            name: Alg.Variant.RSA_PSS,
        },
        extractable,
        keyUsages
    )) as RsaPssCryptoKeyPair;

    return proxy.proxifyKeyPair<
        RsaPssCryptoKeyPair,
        RsaPssPrivCryptoKey,
        RsaPssProxiedPrivCryptoKey,
        RsaPssPubCryptoKey,
        RsaPssProxiedPubCryptoKey
    >(handlers)(keyPair);
};

/**
 * Import an RSA_PSS public or private key
 * @example
 * ```ts
 * const key = await RSA_PSS.importKey("jwk", pubKey, { hash: "SHA-512" }, true, ['verify']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<RsaPssProxiedPrivCryptoKey | RsaPssProxiedPubCryptoKey> => {
    const importedKey = await RsaShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.RSA_PSS },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<
            RsaPssPrivCryptoKey,
            RsaPssProxiedPrivCryptoKey
        >(handlers.privHandler)(importedKey as RsaPssPrivCryptoKey);
    } else {
        return proxy.proxifyKey<RsaPssPubCryptoKey, RsaPssProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as RsaPssPubCryptoKey);
    }
};

/**
 * Export an RSA_PSS public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await RSA_PSS.importKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyJwk = await keyPair.publicKey.importKey("jwk");
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: RsaPssPrivCryptoKey | RsaPssPubCryptoKey
) => RsaShared.exportKey(format, key);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await RSA_PSS.sign(128, keyPair.privateKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await keyPair.privateKey.sign(128, message);
 * ```
 */
export const sign = async (
    saltLength: number,
    key: RsaPssPrivCryptoKey,
    data: BufferSource
) =>
    await RsaShared.sign(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        key,
        data
    );

/**
 * Verify a given signature
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await ECDSA.verify(128, keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify(128, signature, message);
 * ```
 */
export const verify = async (
    saltLength: number,
    key: RsaPssPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
) =>
    await RsaShared.verify(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        key,
        signature,
        data
    );
