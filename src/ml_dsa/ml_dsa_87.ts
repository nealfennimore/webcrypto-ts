/**
 * Code related to ML_DSA_87 (post-quantum signatures).
 * Requires Node.js 24.7.0 or higher.
 * @module
 */
import { ExtendedKeyFormat, ExtendedKeyUsage } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import {
    Alg,
    MlDsaCryptoKeyPair,
    MlDsaCryptoKeys,
    MlDsaPrivCryptoKey,
    MlDsaProxiedCryptoKeyPair,
    MlDsaProxiedPrivCryptoKey,
    MlDsaProxiedPubCryptoKey,
    MlDsaPubCryptoKey,
    MlDsaShared,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    MlDsaPrivCryptoKey,
    MlDsaPubCryptoKey
> = {
    privHandler: {
        get(target: MlDsaPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return (
                        data: BufferSource,
                        algorithm?: Omit<
                            params.EnforcedMlDsaSignParams,
                            "name"
                        >
                    ) => sign(target, data, algorithm);
                case "exportKey":
                    return (format: ExtendedKeyFormat) =>
                        exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: MlDsaPubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return (
                        signature: BufferSource,
                        data: BufferSource,
                        algorithm?: Omit<
                            params.EnforcedMlDsaSignParams,
                            "name"
                        >
                    ) => verify(target, signature, data, algorithm);
                case "exportKey":
                    return (format: ExtendedKeyFormat) =>
                        exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new ML_DSA_87 keypair
 * @example
 * ```ts
 * const keyPair = await ML_DSA_87.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await ML_DSA_87.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ML_DSA_87.generateKey(true, ['sign', 'verify']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: ExtendedKeyUsage[]
): Promise<MlDsaProxiedCryptoKeyPair> => {
    const keyPair = (await MlDsaShared.generateKey(
        { name: Alg.Variant.ML_DSA_87 },
        extractable,
        keyUsages
    )) as MlDsaCryptoKeyPair;

    return proxy.proxifyKeyPair<
        MlDsaCryptoKeyPair,
        MlDsaPrivCryptoKey,
        MlDsaProxiedPrivCryptoKey,
        MlDsaPubCryptoKey,
        MlDsaProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new ML_DSA_87 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await ML_DSA_87.generateKeyPair();
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an ML_DSA_87 public or private key
 * @example
 * ```ts
 * const pubKey = await ML_DSA_87.importKey("raw-public", pubKeyBytes, true, ['verify']);
 * ```
 * @example
 * ```ts
 * const privKey = await ML_DSA_87.importKey("raw-seed", seedBytes, true, ['sign']);
 * ```
 */
export const importKey = async (
    format: ExtendedKeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: ExtendedKeyUsage[]
): Promise<MlDsaProxiedPubCryptoKey | MlDsaProxiedPrivCryptoKey> => {
    const importedKey: MlDsaCryptoKeys = await MlDsaShared.importKey(
        format,
        key,
        { name: Alg.Variant.ML_DSA_87 },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<MlDsaPrivCryptoKey, MlDsaProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as MlDsaPrivCryptoKey);
    } else {
        return proxy.proxifyKey<MlDsaPubCryptoKey, MlDsaProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as MlDsaPubCryptoKey);
    }
};

/**
 * Export an ML_DSA_87 public or private key
 * @example
 * ```ts
 * const pubKeyBytes = await ML_DSA_87.exportKey("raw-public", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const seedBytes = await ML_DSA_87.exportKey("raw-seed", keyPair.privateKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyJwk = await keyPair.publicKey.exportKey("jwk");
 * ```
 */
export const exportKey = async (
    format: ExtendedKeyFormat,
    key: MlDsaPubCryptoKey | MlDsaPrivCryptoKey
) => MlDsaShared.exportKey(format, key);

/**
 * Sign a given payload. Optionally takes a context to associate with
 * the message.
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await ML_DSA_87.sign(keyPair.privateKey.self, message);
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
    key: MlDsaPrivCryptoKey,
    data: BufferSource,
    algorithm: Omit<params.EnforcedMlDsaSignParams, "name"> = {}
): Promise<ArrayBuffer> {
    return await MlDsaShared.sign(
        { ...algorithm, name: Alg.Variant.ML_DSA_87 },
        key,
        data
    );
}

/**
 * Verify a given signature. Optionally takes a context to associate with
 * the message.
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await ML_DSA_87.verify(keyPair.publicKey.self, signature, message);
 * ```
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await keyPair.publicKey.verify(signature, message);
 * ```
 */
export async function verify(
    key: MlDsaPubCryptoKey,
    signature: BufferSource,
    data: BufferSource,
    algorithm: Omit<params.EnforcedMlDsaSignParams, "name"> = {}
): Promise<boolean> {
    return await MlDsaShared.verify(
        { ...algorithm, name: Alg.Variant.ML_DSA_87 },
        key,
        signature,
        data
    );
}
