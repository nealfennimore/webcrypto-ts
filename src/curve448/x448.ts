/**
 * Code related to X448
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
    Curve448Shared,
    X448CryptoKeyPair,
    X448PrivCryptoKey,
    X448ProxiedCryptoKeyPair,
    X448ProxiedPrivCryptoKey,
    X448ProxiedPubCryptoKey,
    X448PubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<X448PrivCryptoKey, X448PubCryptoKey> =
    {
        privHandler: {
            get(target: X448PrivCryptoKey, prop: string) {
                switch (prop) {
                    case "self":
                        return target;
                    case "deriveKey":
                        return (
                            algorithm: Omit<
                                params.EnforcedX448KeyDeriveParams,
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
                                params.EnforcedX448KeyDeriveParams,
                                "name"
                            >,
                            length: number
                        ) => deriveBits(algorithm, target, length);
                    case "exportKey":
                        return (format: KeyFormat) =>
                            exportKey(format, target);
                }

                return Reflect.get(target, prop);
            },
        },
        pubHandler: {
            get(target: X448PubCryptoKey, prop: string) {
                switch (prop) {
                    case "self":
                        return target;
                    case "exportKey":
                        return (format: KeyFormat) =>
                            exportKey(format, target);
                }

                return Reflect.get(target, prop);
            },
        },
    };

/**
 * Generate a new X448 keypair
 * @example
 * ```ts
 * const keyPair = await X448.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKey(true, ['deriveKey', 'deriveBits']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<X448ProxiedCryptoKeyPair> => {
    const keyPair = (await Curve448Shared.generateKey(
        { name: Alg.Variant.X448 },
        extractable,
        keyUsages
    )) as X448CryptoKeyPair;
    return proxy.proxifyKeyPair<
        X448CryptoKeyPair,
        X448PrivCryptoKey,
        X448ProxiedPrivCryptoKey,
        X448PubCryptoKey,
        X448ProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new X448 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await X448.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKeyPair(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKeyPair(true, ['deriveKey', 'deriveBits']);
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an X448 public or private key
 * @example
 * ```ts
 * const pubKey = await X448.importKey("jwk", pubKeyJwk, true, []);
 * ```
 * @example
 * ```ts
 * const privKey = await X448.importKey("jwk", privKeyJwk, true, ['deriveBits', 'deriveKey']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<X448ProxiedPubCryptoKey | X448ProxiedPrivCryptoKey> => {
    const importedKey = await Curve448Shared.importKey(
        format,
        key,
        { name: Alg.Variant.X448 },
        extractable,
        keyUsages
    );
    if (importedKey.type === "private") {
        return proxy.proxifyKey<X448PrivCryptoKey, X448ProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as X448PrivCryptoKey);
    } else {
        return proxy.proxifyKey<X448PubCryptoKey, X448ProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as X448PubCryptoKey);
    }
};
/**
 * Export an X448 public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await X448.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await X448.exportKey("jwk", keyPair.privateKey.self);
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
    key: X448PubCryptoKey | X448PrivCryptoKey
) => Curve448Shared.exportKey(format, key);

/**
 * Derive a shared key between two X448 key pairs.
 * Note that the derived key material is limited to 448 bits,
 * so the derived key type must not require more than that.
 * @example
 * ```ts
 * const keyPair = await X448.generateKey();
 * const otherKeyPair = await X448.generateKey();
 * const aesParams: params.EnforcedAesKeyGenParams = {
 *      name: AES.Alg.Mode.AES_GCM,
 *      length: 256,
 * };
 * let key = await X448.deriveKey(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      aesParams
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKey();
 * const otherKeyPair = await X448.generateKey();
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
    algorithm: Omit<params.EnforcedX448KeyDeriveParams, "name">,
    baseKey: X448PrivCryptoKey,
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
            name: Alg.Variant.X448,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
    );
}

/**
 * Derive a shared bits between two X448 key pairs
 * @example
 * ```ts
 * const keyPair = await X448.generateKey();
 * const otherKeyPair = await X448.generateKey();
 * const bits = await X448.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      128
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await X448.generateKey();
 * const otherKeyPair = await X448.generateKey();
 * const bits = await keyPair.privateKey.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      128
 * );
 * ```
 */
export async function deriveBits(
    algorithm: Omit<params.EnforcedX448KeyDeriveParams, "name">,
    baseKey: X448PrivCryptoKey,
    length: number
): Promise<ArrayBuffer> {
    return await WebCrypto.deriveBits<
        X448PrivCryptoKey,
        params.EnforcedX448KeyDeriveParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.X448,
        },
        baseKey,
        length
    );
}
