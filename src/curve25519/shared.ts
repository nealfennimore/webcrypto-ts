/**
 * Shared code for Curve25519
 * @module
 */
import { AesCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey } from "../hmac/index.js";
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface X25519PubCryptoKey extends CryptoKey {
    _x25519PubCryptoKeyBrand: any;
}
export interface X25519PrivCryptoKey extends CryptoKey {
    _x25519PrivCryptoKeyBrand: any;
}
export interface X25519CryptoKeyPair extends CryptoKeyPair {
    _x25519CryptoKeyPairBrand: any;
    publicKey: X25519PubCryptoKey;
    privateKey: X25519PrivCryptoKey;
}
export interface Ed25519PubCryptoKey extends CryptoKey {
    _ed25519PubCryptoKeyBrand: any;
}
export interface Ed25519PrivCryptoKey extends CryptoKey {
    _ed25519PrivCryptoKeyBrand: any;
}
export interface Ed25519CryptoKeyPair extends CryptoKeyPair {
    _ed25519CryptoKeyPairBrand: any;
    publicKey: Ed25519PubCryptoKey;
    privateKey: Ed25519PrivCryptoKey;
}

export interface Ed25519ProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<Ed25519PubCryptoKey> {
    verify: (signature: BufferSource, data: BufferSource) => Promise<boolean>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface Ed25519ProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<Ed25519PrivCryptoKey> {
    sign: (data: BufferSource) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface Ed25519ProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        Ed25519CryptoKeyPair,
        Ed25519PrivCryptoKey,
        Ed25519ProxiedPrivCryptoKey,
        Ed25519PubCryptoKey,
        Ed25519ProxiedPubCryptoKey
    > {}
export interface X25519ProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<X25519PubCryptoKey> {
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface X25519ProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<X25519PrivCryptoKey> {
    deriveKey: (
        algorithm: Omit<params.EnforcedX25519KeyDeriveParams, "name">,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) => Promise<HmacCryptoKey | AesCryptoKeys>;
    deriveBits: (
        algorithm: Omit<params.EnforcedX25519KeyDeriveParams, "name">,
        length: number
    ) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface X25519ProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        X25519CryptoKeyPair,
        X25519PrivCryptoKey,
        X25519ProxiedPrivCryptoKey,
        X25519PubCryptoKey,
        X25519ProxiedPubCryptoKey
    > {}

export type Curve25519CryptoKeys =
    | X25519PubCryptoKey
    | X25519PrivCryptoKey
    | Ed25519PubCryptoKey
    | Ed25519PrivCryptoKey;
export type Curve25519CryptoKeyPairs =
    | X25519CryptoKeyPair
    | Ed25519CryptoKeyPair;

export namespace Alg {
    export enum Variant {
        Ed25519 = "Ed25519",
        X25519 = "X25519",
    }
    export type Variants = `${Variant}`;
}

export namespace Curve25519Shared {
    export async function generateKey<T extends Curve25519CryptoKeyPairs>(
        algorithm: params.EnforcedCurve25519KeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.generateKey<
            T,
            params.EnforcedCurve25519KeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey<T extends Curve25519CryptoKeys>(
        format: KeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedCurve25519KeyImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<
            T,
            params.EnforcedCurve25519KeyImportParams
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
        key: Curve25519CryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format, key);
    }
}
