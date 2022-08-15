/**
 * @module
 */
import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";

export interface EcdhCryptoKey extends CryptoKey {
    _ecdhCryptoKeyBrand: any;
}
export interface EcdhCryptoKeyPair extends CryptoKeyPair {
    _ecdhCryptoKeyPairBrand: any;
    publicKey: EcdhCryptoKey;
    privateKey: EcdhCryptoKey;
}
export interface EcdsaCryptoKey extends CryptoKey {
    _ecdsaCryptoKeyBrand: any;
}
export interface EcdsaCryptoKeyPair extends CryptoKeyPair {
    _ecdsaCryptoKeyPairBrand: any;
    publicKey: EcdsaCryptoKey;
    privateKey: EcdsaCryptoKey;
}
export type EcCryptoKeys = EcdhCryptoKey | EcdsaCryptoKey;
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
        keyData: BufferSource | JsonWebKey,
        algorithm: params.EnforcedEcKeyImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<T> {
        return await WebCrypto.importKey<T, params.EnforcedEcKeyImportParams>(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        keyData: EcCryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }
}
