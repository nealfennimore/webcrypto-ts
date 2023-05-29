/**
 * Shared code for EC
 * @module
 */
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface EcdhPubCryptoKey extends CryptoKey {
    _ecdhPubCryptoKeyBrand: any;
}
export interface EcdhPrivCryptoKey extends CryptoKey {
    _ecdhPrivCryptoKeyBrand: any;
}
export interface EcdhCryptoKeyPair extends CryptoKeyPair {
    _ecdhCryptoKeyPairBrand: any;
    publicKey: EcdhPubCryptoKey;
    privateKey: EcdhPrivCryptoKey;
}
export interface EcdsaPubCryptoKey extends CryptoKey {
    _ecdsaPubCryptoKeyBrand: any;
}
export interface EcdsaPrivCryptoKey extends CryptoKey {
    _ecdsaPrivCryptoKeyBrand: any;
}
export interface EcdsaCryptoKeyPair extends CryptoKeyPair {
    _ecdsaCryptoKeyPairBrand: any;
    publicKey: EcdsaPubCryptoKey;
    privateKey: EcdsaPrivCryptoKey;
}

export interface EcdsaProxiedPubCryptoKey
    extends proxy.ProxiedPubCryptoKey<EcdsaPubCryptoKey> {
    verify: (
        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
        signature: BufferSource,
        data: BufferSource
    ) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface EcdsaProxiedPrivCryptoKey
    extends proxy.ProxiedPrivCryptoKey<EcdsaPrivCryptoKey> {
    sign: (
        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
        data: BufferSource
    ) => Promise<ArrayBuffer>;

    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface EcdsaProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        EcdsaCryptoKeyPair,
        EcdsaPrivCryptoKey,
        EcdsaProxiedPrivCryptoKey,
        EcdsaPubCryptoKey,
        EcdsaProxiedPubCryptoKey
    > {}

export type EcCryptoKeys =
    | EcdhPubCryptoKey
    | EcdhPrivCryptoKey
    | EcdsaPubCryptoKey
    | EcdsaPrivCryptoKey;
export type EcCryptoKeyPairs = EcdhCryptoKeyPair | EcdsaCryptoKeyPair;

export namespace Alg {
    export enum Variant {
        ECDSA = "ECDSA",
        ECDH = "ECDH",
    }
    export type Variants = `${Variant}`;

    export enum Curve {
        P_256 = "P-256",
        P_384 = "P-384",
        P_521 = "P-521",
    }

    export type Curves = `${Curve}`;
}

export namespace EcShared {
    export async function generateKey<T extends EcCryptoKeyPairs>(
        algorithm: params.EnforcedEcKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.generateKey<T, params.EnforcedEcKeyGenParams>(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey<T extends EcCryptoKeys>(
        format: KeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedEcKeyImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<T, params.EnforcedEcKeyImportParams>(
            format as any,
            key as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        key: EcCryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, key);
    }
}
