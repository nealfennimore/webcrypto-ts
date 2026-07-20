/**
 * Wrapper for node/browser webcrypto
 * @module
 */

import type { ExtendedKeyFormat, ExtendedKeyUsage } from "./key_usages.js";
import { Alg as SHA } from "./sha/shared.js";

/**
 * Result of `encapsulateBits` — a temporary shared secret for the sender and
 * the ciphertext to transmit to the recipient.
 * Requires Node.js 24.7.0 or higher.
 */
export interface EncapsulatedBits {
    sharedKey: ArrayBuffer;
    ciphertext: ArrayBuffer;
}

/**
 * Result of `encapsulateKey` — a temporary shared secret (as a CryptoKey) for
 * the sender and the ciphertext to transmit to the recipient.
 * Requires Node.js 24.7.0 or higher.
 */
export interface EncapsulatedKey<T extends CryptoKey = CryptoKey> {
    sharedKey: T;
    ciphertext: ArrayBuffer;
}

/**
 * SubtleCrypto including the key encapsulation methods from the Modern
 * Algorithms in the Web Cryptography API spec, which are not yet part of
 * the bundled TypeScript DOM types.
 */
interface ExtendedSubtleCrypto extends SubtleCrypto {
    encapsulateBits(
        encapsulationAlgorithm: AlgorithmIdentifier,
        encapsulationKey: CryptoKey
    ): Promise<EncapsulatedBits>;
    encapsulateKey(
        encapsulationAlgorithm: AlgorithmIdentifier,
        encapsulationKey: CryptoKey,
        sharedKeyAlgorithm:
            | AlgorithmIdentifier
            | HmacImportParams
            | AesDerivedKeyParams,
        extractable: boolean,
        usages: KeyUsage[]
    ): Promise<EncapsulatedKey>;
    decapsulateBits(
        decapsulationAlgorithm: AlgorithmIdentifier,
        decapsulationKey: CryptoKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer>;
    decapsulateKey(
        decapsulationAlgorithm: AlgorithmIdentifier,
        decapsulationKey: CryptoKey,
        ciphertext: BufferSource,
        sharedKeyAlgorithm:
            | AlgorithmIdentifier
            | HmacImportParams
            | AesDerivedKeyParams,
        extractable: boolean,
        usages: KeyUsage[]
    ): Promise<CryptoKey>;
}

class CryptoLoader {
    static async load(): Promise<Crypto> {
        // @ts-ignore
        return typeof crypto !== "undefined" // Should match node which includes crypto and window.crypto
            ? Promise.resolve(crypto)
            : ((await (
                  await import("node:crypto")
              ).webcrypto) as Crypto);
    }
}

/**
 * Crypto loader which loads native webcrypto depending on environment
 */
export const _crypto = CryptoLoader.load();

export async function encrypt<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaOaepParams
        | AesCtrParams
        | AesCbcParams
        | AesGcmParams
>(algorithm: U, key: T, data: BufferSource): Promise<ArrayBuffer> {
    return await (await _crypto).subtle.encrypt(algorithm, key, data);
}

export async function decrypt<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaOaepParams
        | AesCtrParams
        | AesCbcParams
        | AesGcmParams
>(algorithm: U, key: T, data: BufferSource): Promise<ArrayBuffer> {
    return await (await _crypto).subtle.decrypt(algorithm, key, data);
}

export async function sign<
    T extends CryptoKey,
    U extends AlgorithmIdentifier | RsaPssParams | EcdsaParams
>(algorithm: U, key: T, data: BufferSource): Promise<ArrayBuffer> {
    return await (await _crypto).subtle.sign(algorithm, key, data);
}

export async function verify<
    T extends CryptoKey,
    U extends AlgorithmIdentifier | RsaPssParams | EcdsaParams
>(
    algorithm: U,
    key: T,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await (await _crypto).subtle.verify(algorithm, key, signature, data);
}

export async function deriveKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | AesDerivedKeyParams
        | HmacImportParams
        | HkdfParams
        | Pbkdf2Params
>(
    algorithm:
        | AlgorithmIdentifier
        | EcdhKeyDeriveParams
        | HkdfParams
        | Pbkdf2Params,
    key: CryptoKey,
    derivedKeyType: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T> {
    return (await (
        await _crypto
    ).subtle.deriveKey(
        algorithm,
        key,
        derivedKeyType,
        extractable,
        keyUsages as KeyUsage[]
    )) as T;
}

export async function deriveBits<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | EcdhKeyDeriveParams
        | HkdfParams
        | Pbkdf2Params
>(algorithm: U, baseKey: T, length: number): Promise<ArrayBuffer> {
    if (length % 8 !== 0) {
        throw new RangeError("Length must be a multiple of 8");
    }
    return await (await _crypto).subtle.deriveBits(algorithm, baseKey, length);
}

export async function wrapKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaOaepParams
        | AesCtrParams
        | AesCbcParams
        | AesGcmParams
>(
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: T,
    wrapAlgorithm: U
): Promise<ArrayBuffer> {
    return await (
        await _crypto
    ).subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm);
}

export async function unwrapKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaOaepParams
        | AesCtrParams
        | AesCbcParams
        | AesGcmParams,
    V extends
        | AlgorithmIdentifier
        | RsaHashedImportParams
        | EcKeyImportParams
        | HmacImportParams
        | AesKeyAlgorithm
>(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: T,
    unwrapAlgorithm: U,
    unwrappedKeyAlgorithm: V,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<CryptoKey> {
    return await (
        await _crypto
    ).subtle.unwrapKey(
        format,
        wrappedKey,
        unwrappingKey,
        unwrapAlgorithm,
        unwrappedKeyAlgorithm,
        extractable,
        keyUsages as KeyUsage[]
    );
}

export async function exportKey<T extends CryptoKey>(
    format: Extract<ExtendedKeyFormat, "jwk">,
    key: T
): Promise<JsonWebKey>;
export async function exportKey<T extends CryptoKey>(
    format: Exclude<ExtendedKeyFormat, "jwk">,
    key: T
): Promise<ArrayBuffer>;
export async function exportKey<T extends CryptoKey>(
    format: ExtendedKeyFormat,
    key: T
): Promise<JsonWebKey | ArrayBuffer>;
export async function exportKey<T extends CryptoKey>(
    format: ExtendedKeyFormat,
    key: T
): Promise<JsonWebKey | ArrayBuffer> {
    if (format === "jwk") {
        return await (await _crypto).subtle.exportKey(format, key);
    }
    return await (
        await _crypto
    ).subtle.exportKey(format as Exclude<KeyFormat, "jwk">, key);
}

export async function importKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaHashedImportParams
        | EcKeyImportParams
        | HmacImportParams
        | AesKeyAlgorithm
>(
    format: Extract<ExtendedKeyFormat, "jwk">,
    key: JsonWebKey,
    algorithm: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T>;
export async function importKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaHashedImportParams
        | EcKeyImportParams
        | HmacImportParams
        | AesKeyAlgorithm
>(
    format: Exclude<ExtendedKeyFormat, "jwk">,
    key: BufferSource,
    algorithm: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T>;
export async function importKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaHashedImportParams
        | EcKeyImportParams
        | HmacImportParams
        | AesKeyAlgorithm
>(
    format: ExtendedKeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T>;
export async function importKey<
    T extends CryptoKey,
    U extends
        | AlgorithmIdentifier
        | RsaHashedImportParams
        | EcKeyImportParams
        | HmacImportParams
        | AesKeyAlgorithm
>(
    format: ExtendedKeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T> {
    if (format === "jwk") {
        return (await (
            await _crypto
        ).subtle.importKey(
            format,
            key as JsonWebKey,
            algorithm,
            extractable,
            keyUsages as KeyUsage[]
        )) as T;
    }

    return (await (
        await _crypto
    ).subtle.importKey(
        format as Exclude<KeyFormat, "jwk">,
        key as BufferSource,
        algorithm,
        extractable,
        keyUsages as KeyUsage[]
    )) as T;
}

export async function generateKey<
    T extends CryptoKeyPair | CryptoKey,
    U extends
        | RsaHashedKeyGenParams
        | EcKeyGenParams
        | AesKeyGenParams
        | HmacKeyGenParams
        | Pbkdf2Params
        | AlgorithmIdentifier
>(
    algorithm: U,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<T> {
    return (await (
        await _crypto
    ).subtle.generateKey(algorithm, extractable, keyUsages as KeyUsage[])) as T;
}

export async function digest<T extends ArrayBuffer>(
    algorithm: SHA.Variants,
    data: BufferSource
): Promise<T> {
    return (await (await _crypto).subtle.digest(algorithm, data)) as T;
}

/**
 * Requires Node.js 24.7.0 or higher.
 */
export async function encapsulateBits<
    T extends CryptoKey,
    U extends AlgorithmIdentifier
>(algorithm: U, encapsulationKey: T): Promise<EncapsulatedBits> {
    const subtle = (await _crypto).subtle as ExtendedSubtleCrypto;
    return await subtle.encapsulateBits(algorithm, encapsulationKey);
}

/**
 * Requires Node.js 24.7.0 or higher.
 */
export async function encapsulateKey<
    T extends CryptoKey,
    S extends CryptoKey,
    U extends AlgorithmIdentifier,
    V extends AlgorithmIdentifier | HmacImportParams | AesDerivedKeyParams
>(
    algorithm: U,
    encapsulationKey: T,
    sharedKeyAlgorithm: V,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<EncapsulatedKey<S>> {
    const subtle = (await _crypto).subtle as ExtendedSubtleCrypto;
    return (await subtle.encapsulateKey(
        algorithm,
        encapsulationKey,
        sharedKeyAlgorithm,
        extractable,
        keyUsages as KeyUsage[]
    )) as EncapsulatedKey<S>;
}

/**
 * Requires Node.js 24.7.0 or higher.
 */
export async function decapsulateBits<
    T extends CryptoKey,
    U extends AlgorithmIdentifier
>(
    algorithm: U,
    decapsulationKey: T,
    ciphertext: BufferSource
): Promise<ArrayBuffer> {
    const subtle = (await _crypto).subtle as ExtendedSubtleCrypto;
    return await subtle.decapsulateBits(
        algorithm,
        decapsulationKey,
        ciphertext
    );
}

/**
 * Requires Node.js 24.7.0 or higher.
 */
export async function decapsulateKey<
    T extends CryptoKey,
    S extends CryptoKey,
    U extends AlgorithmIdentifier,
    V extends AlgorithmIdentifier | HmacImportParams | AesDerivedKeyParams
>(
    algorithm: U,
    decapsulationKey: T,
    ciphertext: BufferSource,
    sharedKeyAlgorithm: V,
    extractable: boolean,
    keyUsages: ExtendedKeyUsage[]
): Promise<S> {
    const subtle = (await _crypto).subtle as ExtendedSubtleCrypto;
    return (await subtle.decapsulateKey(
        algorithm,
        decapsulationKey,
        ciphertext,
        sharedKeyAlgorithm,
        extractable,
        keyUsages as KeyUsage[]
    )) as S;
}
