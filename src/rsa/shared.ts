/**
 * Shared code for RSA
 * @module
 */

import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";

export interface RsaOaepPubCryptoKey extends CryptoKey {
    _rsaOaepPubCryptoKeyBrand: any;
}
export interface RsaOaepPrivCryptoKey extends CryptoKey {
    _rsaOaepPrivCryptoKeyBrand: any;
}
export interface RsaPssPubCryptoKey extends CryptoKey {
    _rsaPssPubCryptoKeyBrand: any;
}
export interface RsaPssPrivCryptoKey extends CryptoKey {
    _rsaPssPrivCryptoKeyBrand: any;
}
export interface RsassaPkcs1V15PubCryptoKey extends CryptoKey {
    _rsassaPkcs1V15PubCryptoKeyBrand: any;
}
export interface RsassaPkcs1V15PrivCryptoKey extends CryptoKey {
    _rsassaPkcs1V15PrivCryptoKeyBrand: any;
}

export type RsaCryptoKeys =
    | RsaOaepPubCryptoKey
    | RsaOaepPrivCryptoKey
    | RsaPssPubCryptoKey
    | RsaPssPrivCryptoKey
    | RsassaPkcs1V15PubCryptoKey
    | RsassaPkcs1V15PrivCryptoKey;

export interface RsaOaepCryptoKeyPair extends CryptoKeyPair {
    _rsaOaepCryptoKeyPairBrand: any;
    publicKey: RsaOaepPubCryptoKey;

    privateKey: RsaOaepPrivCryptoKey;
}
export interface RsaPssCryptoKeyPair extends CryptoKeyPair {
    _rsaPssCryptoKeyPairBrand: any;
    publicKey: RsaPssPubCryptoKey;

    privateKey: RsaPssPrivCryptoKey;
}
export interface RsassaPkcs1V15CryptoKeyPair extends CryptoKeyPair {
    _rsassaPkcs1V15CryptoKeyBrand: any;
    publicKey: RsassaPkcs1V15PubCryptoKey;

    privateKey: RsassaPkcs1V15PrivCryptoKey;
}
export type RsaCryptoKeyPairs =
    | RsaOaepCryptoKeyPair
    | RsaPssCryptoKeyPair
    | RsassaPkcs1V15CryptoKeyPair;

export namespace Alg {
    export enum Variant {
        RSA_OAEP = "RSA-OAEP",
        RSA_PSS = "RSA-PSS",
        RSASSA_PKCS1_v1_5 = "RSASSA-PKCS1-v1_5",
    }
    export type Variants = `${Variant}`;
}

export namespace RsaShared {
    export async function generateKey(
        algorithm: params.EnforcedRsaHashedKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<RsaCryptoKeys | RsaCryptoKeyPairs> {
        return await WebCrypto.generateKey<
            RsaCryptoKeys | RsaCryptoKeyPairs,
            params.EnforcedRsaHashedKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey<T extends RsaCryptoKeys>(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: params.EnforcedRsaHashedImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<
            T,
            params.EnforcedRsaHashedImportParams
        >(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey<T extends RsaCryptoKeys>(
        format: KeyFormat,
        keyData: T
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function sign(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaPssPrivCryptoKey | RsassaPkcs1V15PrivCryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(algorithm, keyData, data);
    }

    export async function verify(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaPssPubCryptoKey | RsassaPkcs1V15PubCryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(algorithm, keyData, signature, data);
    }
}
