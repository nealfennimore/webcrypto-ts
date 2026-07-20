/**
 * Code related to ML_KEM_768 (post-quantum key encapsulation).
 * Requires Node.js 24.7.0 or higher.
 * @module
 */
import { ExtendedKeyFormat, ExtendedKeyUsage } from "../key_usages.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    MlKemCryptoKeyPair,
    MlKemCryptoKeys,
    MlKemPrivCryptoKey,
    MlKemProxiedCryptoKeyPair,
    MlKemProxiedPrivCryptoKey,
    MlKemProxiedPubCryptoKey,
    MlKemPubCryptoKey,
    MlKemShared,
    MlKemSharedCryptoKeys,
    MlKemSharedKeyParams,
} from "./shared.js";

const handlers: proxy.ProxyKeyPairHandlers<
    MlKemPrivCryptoKey,
    MlKemPubCryptoKey
> = {
    privHandler: {
        get(target: MlKemPrivCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "decapsulateBits":
                    return (ciphertext: BufferSource) =>
                        decapsulateBits(target, ciphertext);
                case "decapsulateKey":
                    return (
                        ciphertext: BufferSource,
                        sharedKeyAlgorithm: MlKemSharedKeyParams,
                        extractable?: boolean,
                        keyUsages?: ExtendedKeyUsage[]
                    ) =>
                        decapsulateKey(
                            target,
                            ciphertext,
                            sharedKeyAlgorithm,
                            extractable,
                            keyUsages
                        );
                case "exportKey":
                    return (format: ExtendedKeyFormat) =>
                        exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
    pubHandler: {
        get(target: MlKemPubCryptoKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "encapsulateBits":
                    return () => encapsulateBits(target);
                case "encapsulateKey":
                    return (
                        sharedKeyAlgorithm: MlKemSharedKeyParams,
                        extractable?: boolean,
                        keyUsages?: ExtendedKeyUsage[]
                    ) =>
                        encapsulateKey(
                            target,
                            sharedKeyAlgorithm,
                            extractable,
                            keyUsages
                        );
                case "exportKey":
                    return (format: ExtendedKeyFormat) =>
                        exportKey(format, target);
            }

            return Reflect.get(target, prop);
        },
    },
};

/**
 * Generate a new ML_KEM_768 keypair
 * @example
 * ```ts
 * const keyPair = await ML_KEM_768.generateKey();
 * ```
 * @example
 * ```ts
 * const keyPair = await ML_KEM_768.generateKey(false);
 * ```
 * @example
 * ```ts
 * const keyPair = await ML_KEM_768.generateKey(true, ['encapsulateBits', 'decapsulateBits']);
 * ```
 */
export const generateKey = async (
    extractable?: boolean,
    keyUsages?: ExtendedKeyUsage[]
): Promise<MlKemProxiedCryptoKeyPair> => {
    const keyPair = (await MlKemShared.generateKey(
        { name: Alg.Variant.ML_KEM_768 },
        extractable,
        keyUsages
    )) as MlKemCryptoKeyPair;

    return proxy.proxifyKeyPair<
        MlKemCryptoKeyPair,
        MlKemPrivCryptoKey,
        MlKemProxiedPrivCryptoKey,
        MlKemPubCryptoKey,
        MlKemProxiedPubCryptoKey
    >(handlers)(keyPair);
};
/**
 * Generate a new ML_KEM_768 keypair
 * @alias generateKey
 * @example
 * ```ts
 * const keyPair = await ML_KEM_768.generateKeyPair();
 * ```
 */
export const generateKeyPair = generateKey;

/**
 * Import an ML_KEM_768 public or private key. Note that a public key
 * must be imported with encapsulation usages, and a private key with
 * decapsulation usages.
 * @example
 * ```ts
 * const pubKey = await ML_KEM_768.importKey("raw-public", pubKeyBytes, true, ['encapsulateKey', 'encapsulateBits']);
 * ```
 * @example
 * ```ts
 * const privKey = await ML_KEM_768.importKey("raw-seed", seedBytes, true, ['decapsulateKey', 'decapsulateBits']);
 * ```
 */
export const importKey = async (
    format: ExtendedKeyFormat,
    key: BufferSource | JsonWebKey,
    extractable?: boolean,
    keyUsages?: ExtendedKeyUsage[]
): Promise<MlKemProxiedPubCryptoKey | MlKemProxiedPrivCryptoKey> => {
    const importedKey: MlKemCryptoKeys = await MlKemShared.importKey(
        format,
        key,
        { name: Alg.Variant.ML_KEM_768 },
        extractable,
        keyUsages
    );

    if (importedKey.type === "private") {
        return proxy.proxifyKey<MlKemPrivCryptoKey, MlKemProxiedPrivCryptoKey>(
            handlers.privHandler
        )(importedKey as MlKemPrivCryptoKey);
    } else {
        return proxy.proxifyKey<MlKemPubCryptoKey, MlKemProxiedPubCryptoKey>(
            handlers.pubHandler
        )(importedKey as MlKemPubCryptoKey);
    }
};

/**
 * Export an ML_KEM_768 public or private key
 * @example
 * ```ts
 * const pubKeyBytes = await ML_KEM_768.exportKey("raw-public", keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const seedBytes = await ML_KEM_768.exportKey("raw-seed", keyPair.privateKey.self);
 * ```
 * @example
 * ```ts
 * const pubKeyBytes = await keyPair.publicKey.exportKey("raw-public");
 * ```
 */
export const exportKey = async (
    format: ExtendedKeyFormat,
    key: MlKemPubCryptoKey | MlKemPrivCryptoKey
) => MlKemShared.exportKey(format, key);

/**
 * Encapsulate a temporary shared secret (256 bits) for the holder of the
 * given public key. Returns the shared secret and the ciphertext to
 * transmit to the recipient.
 * @example
 * ```ts
 * const { sharedKey, ciphertext } = await ML_KEM_768.encapsulateBits(keyPair.publicKey.self);
 * ```
 * @example
 * ```ts
 * const { sharedKey, ciphertext } = await keyPair.publicKey.encapsulateBits();
 * ```
 */
export async function encapsulateBits(
    key: MlKemPubCryptoKey
): Promise<WebCrypto.EncapsulatedBits> {
    return await MlKemShared.encapsulateBits(
        { name: Alg.Variant.ML_KEM_768 },
        key
    );
}

/**
 * Encapsulate a temporary shared key for the holder of the given public
 * key. Returns the shared key as a CryptoKey and the ciphertext to
 * transmit to the recipient. Note that the ML-KEM shared secret is
 * always 256 bits, so the shared key type must not require more than that.
 * @example
 * ```ts
 * const { sharedKey, ciphertext } = await ML_KEM_768.encapsulateKey(
 *      keyPair.publicKey.self,
 *      { name: "AES-GCM", length: 256 }
 * );
 * ```
 * @example
 * ```ts
 * const { sharedKey, ciphertext } = await keyPair.publicKey.encapsulateKey(
 *      { name: "AES-GCM", length: 256 }
 * );
 * ```
 */
export async function encapsulateKey(
    key: MlKemPubCryptoKey,
    sharedKeyAlgorithm: MlKemSharedKeyParams,
    extractable: boolean = true,
    keyUsages?: ExtendedKeyUsage[]
): Promise<WebCrypto.EncapsulatedKey<MlKemSharedCryptoKeys>> {
    return await MlKemShared.encapsulateKey(
        { name: Alg.Variant.ML_KEM_768 },
        key,
        sharedKeyAlgorithm,
        extractable,
        keyUsages
    );
}

/**
 * Decapsulate a received ciphertext with the private key, recovering the
 * shared secret (256 bits) as an ArrayBuffer.
 * @example
 * ```ts
 * const sharedKey = await ML_KEM_768.decapsulateBits(keyPair.privateKey.self, ciphertext);
 * ```
 * @example
 * ```ts
 * const sharedKey = await keyPair.privateKey.decapsulateBits(ciphertext);
 * ```
 */
export async function decapsulateBits(
    key: MlKemPrivCryptoKey,
    ciphertext: BufferSource
): Promise<ArrayBuffer> {
    return await MlKemShared.decapsulateBits(
        { name: Alg.Variant.ML_KEM_768 },
        key,
        ciphertext
    );
}

/**
 * Decapsulate a received ciphertext with the private key, recovering the
 * shared key as a CryptoKey.
 * @example
 * ```ts
 * const sharedKey = await ML_KEM_768.decapsulateKey(
 *      keyPair.privateKey.self,
 *      ciphertext,
 *      { name: "AES-GCM", length: 256 }
 * );
 * ```
 * @example
 * ```ts
 * const sharedKey = await keyPair.privateKey.decapsulateKey(
 *      ciphertext,
 *      { name: "AES-GCM", length: 256 }
 * );
 * ```
 */
export async function decapsulateKey(
    key: MlKemPrivCryptoKey,
    ciphertext: BufferSource,
    sharedKeyAlgorithm: MlKemSharedKeyParams,
    extractable: boolean = true,
    keyUsages?: ExtendedKeyUsage[]
): Promise<MlKemSharedCryptoKeys> {
    return await MlKemShared.decapsulateKey(
        { name: Alg.Variant.ML_KEM_768 },
        key,
        ciphertext,
        sharedKeyAlgorithm,
        extractable,
        keyUsages
    );
}
