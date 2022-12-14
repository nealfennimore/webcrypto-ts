/**
 * Wrapper for node/browser webcrypto
 * @module
 */

import { Alg as SHA } from "./sha/shared.js";

class CryptoLoader {
    static async load(): Promise<Crypto> {
        // @ts-ignore
        return typeof crypto !== "undefined" // Should match node which includes crypto and window.crypto
            ? Promise.resolve(crypto)
            : await (
                  await import("node:crypto")
              ).webcrypto;
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
    keyUsages: KeyUsage[]
): Promise<T> {
    return (await (
        await _crypto
    ).subtle.deriveKey(
        algorithm,
        key,
        derivedKeyType,
        extractable,
        keyUsages
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
    keyUsages: KeyUsage[]
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
        keyUsages
    );
}

export async function exportKey<T extends CryptoKey>(
    format: Extract<KeyFormat, "jwk">,
    key: T
): Promise<JsonWebKey>;
export async function exportKey<T extends CryptoKey>(
    format: Exclude<KeyFormat, "jwk">,
    key: T
): Promise<ArrayBuffer>;
export async function exportKey<T extends CryptoKey>(
    format: KeyFormat,
    key: T
): Promise<JsonWebKey | ArrayBuffer> {
    if (format === "jwk") {
        return await (await _crypto).subtle.exportKey(format, key);
    }
    return await (await _crypto).subtle.exportKey(format, key);
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
    format: Extract<KeyFormat, "jwk">,
    key: JsonWebKey,
    algorithm: U,
    extractable: boolean,
    keyUsages: KeyUsage[]
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
    format: Exclude<KeyFormat, "jwk">,
    key: BufferSource,
    algorithm: U,
    extractable: boolean,
    keyUsages: KeyUsage[]
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
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: U,
    extractable: boolean,
    keyUsages: KeyUsage[]
): Promise<T> {
    if (format === "jwk") {
        return (await (
            await _crypto
        ).subtle.importKey(
            format,
            key as JsonWebKey,
            algorithm,
            extractable,
            keyUsages
        )) as T;
    }

    return (await (
        await _crypto
    ).subtle.importKey(
        format,
        key as BufferSource,
        algorithm,
        extractable,
        keyUsages
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
>(algorithm: U, extractable: boolean, keyUsages: KeyUsage[]): Promise<T> {
    return (await (
        await _crypto
    ).subtle.generateKey(algorithm, extractable, keyUsages)) as T;
}

export async function digest<T extends ArrayBuffer>(
    algorithm: SHA.Variants,
    data: BufferSource
): Promise<T> {
    return (await (await _crypto).subtle.digest(algorithm, data)) as T;
}
