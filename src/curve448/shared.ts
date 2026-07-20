/**
 * Shared code for Curve448
 * @module
 */
import { AesCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey } from "../hmac/index.js";
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface X448PubCryptoKey extends CryptoKey {
    _x448PubCryptoKeyBrand: any;
}
export interface X448PrivCryptoKey extends CryptoKey {
    _x448PrivCryptoKeyBrand: any;
}
export interface X448CryptoKeyPair extends CryptoKeyPair {
    _x448CryptoKeyPairBrand: any;
    publicKey: X448PubCryptoKey;
    privateKey: X448PrivCryptoKey;
}
export interface Ed448PubCryptoKey extends CryptoKey {
    _ed448PubCryptoKeyBrand: any;
}
export interface Ed448PrivCryptoKey extends CryptoKey {
    _ed448PrivCryptoKeyBrand: any;
}
export interface Ed448CryptoKeyPair extends CryptoKeyPair {
    _ed448CryptoKeyPairBrand: any;
    publicKey: Ed448PubCryptoKey;
    privateKey: Ed448PrivCryptoKey;
}

export interface Ed448ProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<Ed448PubCryptoKey> {
    verify: (
        signature: BufferSource,
        data: BufferSource,
        algorithm?: Omit<params.EnforcedEd448Params, "name">
    ) => Promise<boolean>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface Ed448ProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<Ed448PrivCryptoKey> {
    sign: (
        data: BufferSource,
        algorithm?: Omit<params.EnforcedEd448Params, "name">
    ) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface Ed448ProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        Ed448CryptoKeyPair,
        Ed448PrivCryptoKey,
        Ed448ProxiedPrivCryptoKey,
        Ed448PubCryptoKey,
        Ed448ProxiedPubCryptoKey
    > {}
export interface X448ProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<X448PubCryptoKey> {
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface X448ProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<X448PrivCryptoKey> {
    deriveKey: (
        algorithm: Omit<params.EnforcedX448KeyDeriveParams, "name">,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) => Promise<HmacCryptoKey | AesCryptoKeys>;
    deriveBits: (
        algorithm: Omit<params.EnforcedX448KeyDeriveParams, "name">,
        length: number
    ) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface X448ProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        X448CryptoKeyPair,
        X448PrivCryptoKey,
        X448ProxiedPrivCryptoKey,
        X448PubCryptoKey,
        X448ProxiedPubCryptoKey
    > {}

export type Curve448CryptoKeys =
    | X448PubCryptoKey
    | X448PrivCryptoKey
    | Ed448PubCryptoKey
    | Ed448PrivCryptoKey;
export type Curve448CryptoKeyPairs = X448CryptoKeyPair | Ed448CryptoKeyPair;

export namespace Alg {
    export enum Variant {
        Ed448 = "Ed448",
        X448 = "X448",
    }
    export type Variants = `${Variant}`;
}

export namespace Curve448Shared {
    export async function generateKey<T extends Curve448CryptoKeyPairs>(
        algorithm: params.EnforcedCurve448KeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.generateKey<
            T,
            params.EnforcedCurve448KeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey<T extends Curve448CryptoKeys>(
        format: KeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedCurve448KeyImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<
            T,
            params.EnforcedCurve448KeyImportParams
        >(
            format,
            key,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        key: Curve448CryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format, key);
    }
}
