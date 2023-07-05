/**
 * Code related to ECDH
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
    EcShared,
    EcdhCryptoKeyPair,
    EcdhPrivCryptoKey,
    EcdhProxiedCryptoKeyPair,
    EcdhProxiedPrivCryptoKey,
    EcdhProxiedPubCryptoKey,
    EcdhPubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    EcdhPrivCryptoKey,
    EcdhPubCryptoKey
> = {
    privHandler: {
        get(target: EcdhPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "deriveKey":
                    return (
                        algorithm: Omit<
                            params.EnforcedEcdhKeyDeriveParams,
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
                            params.EnforcedEcdhKeyDeriveParams,
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
        get(target: EcdhPubCryptoKey, prop: string) {
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
 * Generate a new ECDH keypair
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey({ namedCurve: "P-256" }, false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey({ namedCurve: "P-256" }, true, ['deriveKey', 'deriveBits']);
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhProxiedCryptoKeyPair> => {
    const keyPair = (await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    )) as EcdhCryptoKeyPair;
    return proxy.proxifyKeyPair<
        EcdhCryptoKeyPair,
        EcdhPrivCryptoKey,
        EcdhProxiedPrivCryptoKey,
        EcdhPubCryptoKey,
        EcdhProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new ECDH keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKeyPair({ namedCurve: "P-256" }, false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKeyPair({ namedCurve: "P-256" }, true, ['deriveKey', 'deriveBits']);
 */
export const generateKeyPair = generateKey;

/**
 * Import an ECDH public or private key
 * @example
 * ```ts
 * const pubKey = await ECDH.importKey("jwk", pubKeyJwk, { namedCurve: "P-521" }, true, []);
 * ```
 * @example
 * ```ts
 * const privKey = await ECDH.importKey("jwk", privKeyJwk, { namedCurve: "P-521" }, true, ['deriveBits', 'deriveKey']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedEcKeyImportParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhProxiedPubCryptoKey | EcdhProxiedPrivCryptoKey> => {
    const importedKey = await EcShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    );
    if (importedKey.type === "private") {
        return proxy.proxifyKey<EcdhPrivCryptoKey, EcdhProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as EcdhPrivCryptoKey);
    } else {
        return proxy.proxifyKey<EcdhPubCryptoKey, EcdhProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as EcdhPubCryptoKey);
    }
};
/**
 * Export an ECDH public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await ECDH.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await ECDH.exportKey("jwk", keyPair.privateKey.self);
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
    key: EcdhPubCryptoKey | EcdhPrivCryptoKey
) => EcShared.exportKey(format, key);

/**
 * Derive a shared key between two ECDH key pairs
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * let key = await ECDH.deriveKey(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      hmacParams
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * let key = await keyPair.privateKey.deriveKey(
 *      { public: otherKeyPair.publicKey.self },
 *      hmacParams
 * );
 * ```
 */
export async function deriveKey(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhPrivCryptoKey,
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
            name: Alg.Variant.ECDH,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
    );
}

/**
 * Derive a shared bits between two ECDH key pairs
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const bits = await ECDH.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      keyPair.privateKey.self,
 *      128
 * );
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const bits = await keyPair.privateKey.deriveBits(
 *      { public: otherKeyPair.publicKey.self },
 *      128
 * );
 * ```
 */
export async function deriveBits(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhPrivCryptoKey,
    length: number
): Promise<ArrayBuffer> {
    return await WebCrypto.deriveBits<
        EcdhPrivCryptoKey,
        params.EnforcedEcdhKeyDeriveParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDH,
        },
        baseKey,
        length
    );
}
