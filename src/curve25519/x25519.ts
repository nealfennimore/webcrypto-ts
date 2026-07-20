/**
 * Code related to X25519
 * @module
 */
import { AesCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey } from "../hmac/index.js";
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    Curve25519Shared,
    X25519CryptoKeyPair,
    X25519PrivCryptoKey,
    X25519ProxiedCryptoKeyPair,
    X25519ProxiedPrivCryptoKey,
    X25519ProxiedPubCryptoKey,
    X25519PubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    X25519PrivCryptoKey,
    X25519PubCryptoKey
> = {
    privHandler: {
        get(target: X25519PrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "deriveKey":
                    return (
                        algorithm: Omit<
                            params.EnforcedX25519KeyDeriveParams,
                            "name"
                        >,
                        derivedKeyType:
                            | params.EnforcedAesKeyGenParams
                            | params.EnforcedHmacKeyGenParams,
                        extractable: boolean,
                        keyUsages?: KeyUsage[]
                    ) =>
                        deriveKey(
                            algorithm,
                            target,
                            derivedKeyType,
                            extractable,
                            keyUsages
                        );
                case "deriveBits":
                    return (
                        algorithm: Omit<
                            params.EnforcedX25519KeyDeriveParams,
                            "name"
                        >,
                        length: number
                    ) => deriveBits(algorithm, target, length);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: X25519PubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new X25519 keypair
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey(true, ['deriveKey', 'deriveBits']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<X25519ProxiedCryptoKeyPair> => {
    const keyPair = (await Curve25519Shared.generateKey(
        { name: Alg.Variant.X25519 },
        extractable,
        keyUsages
    )) as X25519CryptoKeyPair;
    return proxy.proxifyKeyPair<
        X25519CryptoKeyPair,
        X25519PrivCryptoKey,
        X25519ProxiedPrivCryptoKey,
        X25519PubCryptoKey,
        X25519ProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new X25519 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await X25519.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKeyPair(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKeyPair(true, ['deriveKey', 'deriveBits']);
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an X25519 public or private key
 * @example
 * ```ts
 * const pubKey = await X25519.importKey("jwk", pubKeyJwk, true, []);
 * ```
 * @example
 * ```ts
 * const privKey = await X25519.importKey("jwk", privKeyJwk, true, ['deriveBits', 'deriveKey']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<X25519ProxiedPubCryptoKey | X25519ProxiedPrivCryptoKey> => {
    const importedKey = await Curve25519Shared.importKey(
        format,
        key,
        { name: Alg.Variant.X25519 },
        extractable,
        keyUsages
    );
    if (importedKey.type === "private") {
        return proxy.proxifyKey<X25519PrivCryptoKey, X25519ProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as X25519PrivCryptoKey);
    } else {
        return proxy.proxifyKey<X25519PubCryptoKey, X25519ProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as X25519PubCryptoKey);
    }
};
/**
 * Export an X25519 public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await X25519.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await X25519.exportKey("jwk", keyPair.privateKey.self);
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
    key: X25519PubCryptoKey | X25519PrivCryptoKey
) => Curve25519Shared.exportKey(format, key);

/**
 * Derive a shared key between two X25519 key pairs.
 * Note that the derived key material is limited to 256 bits,
 * so the derived key type must not require more than that.
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey();
 * const otherKeyPair = await X25519.generateKey();
 * const aesParams: params.EnforcedAesKeyGenParams = {
 *      name: AES.Alg.Mode.AES_GCM,
 *      length: 256,
 * };
 * let key = await X25519.deriveKey(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      aesParams
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey();
 * const otherKeyPair = await X25519.generateKey();
 * const aesParams: params.EnforcedAesKeyGenParams = {
 *      name: AES.Alg.Mode.AES_GCM,
 *      length: 256,
 * };
 * let key = await keyPair.privateKey.deriveKey(
 *      { public: otherKeyPair.publicKey.self },
 *      aesParams
 * );
 * ```
 */
export async function deriveKey(
    algorithm: Omit<params.EnforcedX25519KeyDeriveParams, "name">,
    baseKey: X25519PrivCryptoKey,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<HmacCryptoKey | AesCryptoKeys> {
    return await WebCrypto.deriveKey<
        HmacCryptoKey | AesCryptoKeys,
        params.EnforcedAesKeyGenParams | params.EnforcedHmacKeyGenParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.X25519,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
    );
}

/**
 * Derive a shared bits between two X25519 key pairs
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey();
 * const otherKeyPair = await X25519.generateKey();
 * const bits = await X25519.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      128
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await X25519.generateKey();
 * const otherKeyPair = await X25519.generateKey();
 * const bits = await keyPair.privateKey.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      128
 * );
 * ```
 */
export async function deriveBits(
    algorithm: Omit<params.EnforcedX25519KeyDeriveParams, "name">,
    baseKey: X25519PrivCryptoKey,
    length: number
): Promise<ArrayBuffer> {
    return await WebCrypto.deriveBits<
        X25519PrivCryptoKey,
        params.EnforcedX25519KeyDeriveParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.X25519,
        },
        baseKey,
        length
    );
}
