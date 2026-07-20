/**
 * Code related to Ed25519
 * @module
 */
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    Curve25519Shared,
    Ed25519CryptoKeyPair,
    Ed25519PrivCryptoKey,
    Ed25519ProxiedCryptoKeyPair,
    Ed25519ProxiedPrivCryptoKey,
    Ed25519ProxiedPubCryptoKey,
    Ed25519PubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    Ed25519PrivCryptoKey,
    Ed25519PubCryptoKey
> = {
    privHandler: {
        get(target: Ed25519PrivCryptoKey, prop: string) {
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
        get(target: Ed25519PubCryptoKey, prop: string) {
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
 * Generate a new Ed25519 keypair
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKey(true, ['sign', 'verify']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<Ed25519ProxiedCryptoKeyPair> => {
    const keyPair = (await Curve25519Shared.generateKey(
        { name: Alg.Variant.Ed25519 },
        extractable,
        keyUsages
    )) as Ed25519CryptoKeyPair;

    return proxy.proxifyKeyPair<
        Ed25519CryptoKeyPair,
        Ed25519PrivCryptoKey,
        Ed25519ProxiedPrivCryptoKey,
        Ed25519PubCryptoKey,
        Ed25519ProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new Ed25519 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKeyPair(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed25519.generateKeyPair(true, ['sign', 'verify']);
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an Ed25519 public or private key
 * @example
 * ```ts
 * const pubKey = await Ed25519.importKey("jwk", pubKeyJwk, true, ['verify']);
 * ```
 * @example
 * ```ts
 * const privKey = await Ed25519.importKey("jwk", privKeyJwk, true, ['sign']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<Ed25519ProxiedPubCryptoKey | Ed25519ProxiedPrivCryptoKey> => {
    const importedKey = await Curve25519Shared.importKey(
        format,
        key,
        { name: Alg.Variant.Ed25519 },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<
            Ed25519PrivCryptoKey,
            Ed25519ProxiedPrivCryptoKey
        >(handlers.privHandler)(importedKey as Ed25519PrivCryptoKey);
    } else {
        return proxy.proxifyKey<
            Ed25519PubCryptoKey,
            Ed25519ProxiedPubCryptoKey
        >(handlers.pubHandler)(importedKey as Ed25519PubCryptoKey);
    }
};

/**
 * Export an Ed25519 public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await Ed25519.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await Ed25519.exportKey("jwk", keyPair.privateKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyJwk = await keyPair.publicKey.exportKey("jwk");
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await keyPair.privateKey.exportKey("jwk");
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: Ed25519PubCryptoKey | Ed25519PrivCryptoKey
) => Curve25519Shared.exportKey(format, key);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await Ed25519.sign(keyPair.privateKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await keyPair.privateKey.sign(message);
 * ```
 */
export async function sign(
    key: Ed25519PrivCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<
        Ed25519PrivCryptoKey,
        params.EnforcedEd25519Params
    >(
        {
            name: Alg.Variant.Ed25519,
        },
        key,
        data
    );
}

/**
 * Verify a given signature
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await Ed25519.verify(keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify(signature, message);
 * ```
 */
export async function verify(
    key: Ed25519PubCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await WebCrypto.verify<
        Ed25519PubCryptoKey,
        params.EnforcedEd25519Params
    >(
        {
            name: Alg.Variant.Ed25519,
        },
        key,
        signature,
        data
    );
}
