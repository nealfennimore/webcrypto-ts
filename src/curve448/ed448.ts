/**
 * Code related to Ed448
 * @module
 */
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    Curve448Shared,
    Ed448CryptoKeyPair,
    Ed448PrivCryptoKey,
    Ed448ProxiedCryptoKeyPair,
    Ed448ProxiedPrivCryptoKey,
    Ed448ProxiedPubCryptoKey,
    Ed448PubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    Ed448PrivCryptoKey,
    Ed448PubCryptoKey
> = {
    privHandler: {
        get(target: Ed448PrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return (
                        data: BufferSource,
                        algorithm?: Omit<params.EnforcedEd448Params, "name">
                    ) => sign(target, data, algorithm);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: Ed448PubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return (
                        signature: BufferSource,
                        data: BufferSource,
                        algorithm?: Omit<params.EnforcedEd448Params, "name">
                    ) => verify(target, signature, data, algorithm);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new Ed448 keypair
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKey(true, ['sign', 'verify']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<Ed448ProxiedCryptoKeyPair> => {
    const keyPair = (await Curve448Shared.generateKey(
        { name: Alg.Variant.Ed448 },
        extractable,
        keyUsages
    )) as Ed448CryptoKeyPair;

    return proxy.proxifyKeyPair<
        Ed448CryptoKeyPair,
        Ed448PrivCryptoKey,
        Ed448ProxiedPrivCryptoKey,
        Ed448PubCryptoKey,
        Ed448ProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new Ed448 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKeyPair(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await Ed448.generateKeyPair(true, ['sign', 'verify']);
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an Ed448 public or private key
 * @example
 * ```ts
 * const pubKey = await Ed448.importKey("jwk", pubKeyJwk, true, ['verify']);
 * ```
 * @example
 * ```ts
 * const privKey = await Ed448.importKey("jwk", privKeyJwk, true, ['sign']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<Ed448ProxiedPubCryptoKey | Ed448ProxiedPrivCryptoKey> => {
    const importedKey = await Curve448Shared.importKey(
        format,
        key,
        { name: Alg.Variant.Ed448 },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<Ed448PrivCryptoKey, Ed448ProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as Ed448PrivCryptoKey);
    } else {
        return proxy.proxifyKey<Ed448PubCryptoKey, Ed448ProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as Ed448PubCryptoKey);
    }
};

/**
 * Export an Ed448 public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await Ed448.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await Ed448.exportKey("jwk", keyPair.privateKey.self);
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
    key: Ed448PubCryptoKey | Ed448PrivCryptoKey
) => Curve448Shared.exportKey(format, key);

/**
 * Sign a given payload. Optionally takes a context to associate with
 * the message (non-empty context requires Node.js 24.8.0 or higher).
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await Ed448.sign(keyPair.privateKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await keyPair.privateKey.sign(message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const context = new TextEncoder().encode("a context");
 * const signature = await keyPair.privateKey.sign(message, { context });
 * ```
 */
export async function sign(
    key: Ed448PrivCryptoKey,
    data: BufferSource,
    algorithm: Omit<params.EnforcedEd448Params, "name"> = {}
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<Ed448PrivCryptoKey, params.EnforcedEd448Params>(
        {
            ...algorithm,
            name: Alg.Variant.Ed448,
        },
        key,
        data
    );
}

/**
 * Verify a given signature. Optionally takes a context to associate with
 * the message (non-empty context requires Node.js 24.8.0 or higher).
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await Ed448.verify(keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify(signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const context = new TextEncoder().encode("a context");
 * const isVerified = await keyPair.publicKey.verify(signature, message, { context });
 * ```
 */
export async function verify(
    key: Ed448PubCryptoKey,
    signature: BufferSource,
    data: BufferSource,
    algorithm: Omit<params.EnforcedEd448Params, "name"> = {}
): Promise<boolean> {
    return await WebCrypto.verify<
        Ed448PubCryptoKey,
        params.EnforcedEd448Params
    >(
        {
            ...algorithm,
            name: Alg.Variant.Ed448,
        },
        key,
        signature,
        data
    );
}
