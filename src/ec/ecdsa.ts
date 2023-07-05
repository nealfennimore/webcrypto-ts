/**
 * Code related to ECDSA
 * @module
 */
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    EcShared,
    EcdsaCryptoKeyPair,
    EcdsaPrivCryptoKey,
    EcdsaProxiedCryptoKeyPair,
    EcdsaProxiedPrivCryptoKey,
    EcdsaProxiedPubCryptoKey,
    EcdsaPubCryptoKey,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    EcdsaPrivCryptoKey,
    EcdsaPubCryptoKey
> = {
    privHandler: {
        get(target: EcdsaPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return (
                        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
                        data: BufferSource
                    ) => sign(algorithm, target, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: EcdsaPubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return (
                        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
                        signature: BufferSource,
                        data: BufferSource
                    ) => verify(algorithm, target, signature, data);
                case "exportKey":
                    return (format: KeyFormat) => exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new ECDSA keypair
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKey({ namedCurve: "P-256" }, false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKey({ namedCurve: "P-256" }, true, ['sign', 'verify']);
 * ```
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdsaProxiedCryptoKeyPair> => {
    const keyPair = (await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDSA },
        extractable,
        keyUsages
    )) as EcdsaCryptoKeyPair;

    return proxy.proxifyKeyPair<
        EcdsaCryptoKeyPair,
        EcdsaPrivCryptoKey,
        EcdsaProxiedPrivCryptoKey,
        EcdsaPubCryptoKey,
        EcdsaProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new ECDSA keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKeyPair();
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKeyPair({ namedCurve: "P-256" }, false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKeyPair({ namedCurve: "P-256" }, true, ['sign', 'verify']);
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an ECDSA public or private key
 * @example
 * ```ts
 * const pubKey = await ECDSA.importKey("jwk", pubKeyJwk, { namedCurve: "P-521" }, true, ['verify']);
 * ```
 * @example
 * ```ts
 * const privKey = await ECDSA.importKey("jwk", privKeyJwk, { namedCurve: "P-521" }, true, ['sign']);
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
): Promise<EcdsaProxiedPubCryptoKey | EcdsaProxiedPrivCryptoKey> => {
    const importedKey = await EcShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.ECDSA },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<EcdsaPrivCryptoKey, EcdsaProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as EcdsaPrivCryptoKey);
    } else {
        return proxy.proxifyKey<EcdsaPubCryptoKey, EcdsaProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as EcdsaPubCryptoKey);
    }
};

/**
 * Export an ECDSA public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await ECDSA.exportKey("jwk", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const privKeyJwk = await ECDSA.exportKey("jwk", keyPair.privateKey.self);
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
    key: EcdsaPubCryptoKey | EcdsaPrivCryptoKey
) => EcShared.exportKey(format, key);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await ECDSA.sign({hash: "SHA-512"}, keyPair.privateKey.self, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await keyPair.privateKey.sign({hash: "SHA-512"}, message);
 * ```
 */
export async function sign(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    key: EcdsaPrivCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<EcdsaPrivCryptoKey, params.EnforcedEcdsaParams>(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
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
 * const isVerified = await ECDSA.verify({hash: "SHA-512"}, keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify({hash: "SHA-512"}, signature, message);
 * ```
 */
export async function verify(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    key: EcdsaPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await WebCrypto.verify<
        EcdsaPubCryptoKey,
        params.EnforcedEcdsaParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
        },
        key,
        signature,
        data
    );
}
