import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";

export interface RsaOaepCryptoKey extends CryptoKey {
    _rsaOaepCryptoKeyBrand: any;
}
export interface RsaPssCryptoKey extends CryptoKey {
    _rsaPssCryptoKeyBrand: any;
}
export interface RsassaPkcs1V15CryptoKey extends CryptoKey {
    _rsassaPkcs1V15CryptoKeyBrand: any;
}

export type RsaCryptoKeys =
    | RsaOaepCryptoKey
    | RsaPssCryptoKey
    | RsassaPkcs1V15CryptoKey;
export interface RsaOaepCryptoKeyPair extends CryptoKeyPair {
    _rsaOaepCryptoKeyPairBrand: any;
    publicKey: RsaOaepCryptoKey;

    privateKey: RsaOaepCryptoKey;
}
export interface RsaPssCryptoKeyPair extends CryptoKeyPair {
    _rsaPssCryptoKeyPairBrand: any;
    publicKey: RsaPssCryptoKey;

    privateKey: RsaPssCryptoKey;
}
export interface RsassaPkcs1V15CryptoKeyPair extends CryptoKeyPair {
    _rsassaPkcs1V15CryptoKeyBrand: any;
    publicKey: RsassaPkcs1V15CryptoKey;

    privateKey: RsassaPkcs1V15CryptoKey;
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
        keyData: RsaCryptoKeys,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(algorithm, keyData, data);
    }

    export async function verify(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaCryptoKeys,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(algorithm, keyData, signature, data);
    }
}
