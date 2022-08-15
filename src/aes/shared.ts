/**
 * Shared code for AES
 * @module
 */

import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";

export interface AesGcmCryptoKey extends CryptoKey {
    _aesGcmKeyBrand: any;
}

export interface AesKwCryptoKey extends CryptoKey {
    _aesKwKeyBrand: any;
}

export interface AesCtrCryptoKey extends CryptoKey {
    _aesCtrKeyBrand: any;
}

export interface AesCbcCryptoKey extends CryptoKey {
    _aesCbcKeyBrand: any;
}

export type AesCryptoKeys =
    | AesCbcCryptoKey
    | AesKwCryptoKey
    | AesGcmCryptoKey
    | AesCtrCryptoKey;

export namespace Alg {
    export enum Mode {
        AES_CBC = "AES-CBC",
        AES_CTR = "AES-CTR",
        AES_GCM = "AES-GCM",
        AES_KW = "AES-KW",
    }

    export type Modes = `${Mode}`;
}

export namespace AesShared {
    export async function generateKey<T extends CryptoKey>(
        algorithm: params.EnforcedAesKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.generateKey<T, params.EnforcedAesKeyGenParams>(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey<T extends CryptoKey>(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: params.EnforcedAesKeyAlgorithms,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<T, params.EnforcedAesKeyAlgorithms>(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey<T extends CryptoKey>(
        format: KeyFormat,
        keyData: T
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function encrypt<T extends CryptoKey>(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        keyData: T,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.encrypt(algorithm, keyData, plaintext);
    }

    export async function decrypt<T extends CryptoKey>(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        keyData: T,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.decrypt(algorithm, keyData, ciphertext);
    }

    export async function wrapKey<T extends CryptoKey>(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: T,
        wrapAlgorithm: params.EnforcedAesParams
    ): Promise<ArrayBuffer> {
        return await WebCrypto.wrapKey(
            format as any,
            key,
            wrappingkey,
            wrapAlgorithm
        );
    }
    export async function unwrapKey<T extends CryptoKey>(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: T,
        unwrappingKeyAlgorithm: params.EnforcedAesParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        return await WebCrypto.unwrapKey(
            format as any,
            wrappedKey,
            unwrappingKey,
            unwrappingKeyAlgorithm,
            wrappedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(wrappedKeyAlgorithm.name)
        );
    }
}
