/**
 * Shared code for AES
 * @module
 */

import { getKeyUsagePairsByAlg } from "../key_usages.js";
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
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedAesKeyAlgorithms,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<T, params.EnforcedAesKeyAlgorithms>(
            format as any,
            key as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey<T extends CryptoKey>(
        format: KeyFormat,
        key: T
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, key);
    }

    export async function encrypt<T extends CryptoKey>(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        key: T,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.encrypt(algorithm, key, data);
    }

    export async function decrypt<T extends CryptoKey>(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        key: T,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.decrypt(algorithm, key, data);
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
