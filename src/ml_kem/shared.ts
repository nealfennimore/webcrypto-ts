/**
 * Shared code for ML-KEM (post-quantum key encapsulation).
 * Requires Node.js 24.7.0 or higher.
 * @module
 */
import { AesCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey } from "../hmac/index.js";
import {
    ExtendedKeyFormat,
    ExtendedKeyUsage,
    getKeyUsagePairsByAlg,
} from "../key_usages.js";
import { KmacCryptoKey } from "../kmac/shared.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface MlKemPubCryptoKey extends CryptoKey {
    _mlKemPubCryptoKeyBrand: any;
}
export interface MlKemPrivCryptoKey extends CryptoKey {
    _mlKemPrivCryptoKeyBrand: any;
}
export interface MlKemCryptoKeyPair extends CryptoKeyPair {
    _mlKemCryptoKeyPairBrand: any;
    publicKey: MlKemPubCryptoKey;
    privateKey: MlKemPrivCryptoKey;
}

/**
 * Key types that an encapsulated shared key can be imported as.
 */
export type MlKemSharedCryptoKeys =
    | HmacCryptoKey
    | AesCryptoKeys
    | KmacCryptoKey;
/**
 * Algorithms that an encapsulated shared key can be imported for.
 * Note that the ML-KEM shared secret is always 256 bits.
 */
export type MlKemSharedKeyParams =
    | params.EnforcedAesKeyGenParams
    | params.EnforcedHmacImportParams
    | params.EnforcedKmacImportParams;

export interface MlKemProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<MlKemPubCryptoKey> {
    encapsulateBits: () => Promise<WebCrypto.EncapsulatedBits>;
    encapsulateKey: (
        sharedKeyAlgorithm: MlKemSharedKeyParams,
        extractable?: boolean,
        keyUsages?: ExtendedKeyUsage[]
    ) => Promise<WebCrypto.EncapsulatedKey<MlKemSharedCryptoKeys>>;

    exportKey: (
        format: ExtendedKeyFormat
    ) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface MlKemProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<MlKemPrivCryptoKey> {
    decapsulateBits: (ciphertext: BufferSource) => Promise<ArrayBuffer>;
    decapsulateKey: (
        ciphertext: BufferSource,
        sharedKeyAlgorithm: MlKemSharedKeyParams,
        extractable?: boolean,
        keyUsages?: ExtendedKeyUsage[]
    ) => Promise<MlKemSharedCryptoKeys>;

    exportKey: (
        format: ExtendedKeyFormat
    ) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface MlKemProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        MlKemCryptoKeyPair,
        MlKemPrivCryptoKey,
        MlKemProxiedPrivCryptoKey,
        MlKemPubCryptoKey,
        MlKemProxiedPubCryptoKey
    > {}

export type MlKemCryptoKeys = MlKemPubCryptoKey | MlKemPrivCryptoKey;

export namespace Alg {
    export enum Variant {
        ML_KEM_512 = "ML-KEM-512",
        ML_KEM_768 = "ML-KEM-768",
        ML_KEM_1024 = "ML-KEM-1024",
    }
    export type Variants = `${Variant}`;
}

export namespace MlKemShared {
    export async function generateKey(
        algorithm: params.EnforcedMlKemKeyGenParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<MlKemCryptoKeyPair> {
        return await WebCrypto.generateKey<
            MlKemCryptoKeyPair,
            params.EnforcedMlKemKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: ExtendedKeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedMlKemImportParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<MlKemCryptoKeys> {
        return await WebCrypto.importKey<
            MlKemCryptoKeys,
            params.EnforcedMlKemImportParams
        >(
            format,
            key,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: ExtendedKeyFormat,
        key: MlKemCryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format, key);
    }

    export async function encapsulateBits(
        algorithm: params.EnforcedMlKemEncapsulateParams,
        encapsulationKey: MlKemPubCryptoKey
    ): Promise<WebCrypto.EncapsulatedBits> {
        return await WebCrypto.encapsulateBits(algorithm, encapsulationKey);
    }

    export async function encapsulateKey(
        algorithm: params.EnforcedMlKemEncapsulateParams,
        encapsulationKey: MlKemPubCryptoKey,
        sharedKeyAlgorithm: MlKemSharedKeyParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<WebCrypto.EncapsulatedKey<MlKemSharedCryptoKeys>> {
        return await WebCrypto.encapsulateKey<
            MlKemPubCryptoKey,
            MlKemSharedCryptoKeys,
            params.EnforcedMlKemEncapsulateParams,
            MlKemSharedKeyParams
        >(
            algorithm,
            encapsulationKey,
            sharedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(sharedKeyAlgorithm.name)
        );
    }

    export async function decapsulateBits(
        algorithm: params.EnforcedMlKemEncapsulateParams,
        decapsulationKey: MlKemPrivCryptoKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.decapsulateBits(
            algorithm,
            decapsulationKey,
            ciphertext
        );
    }

    export async function decapsulateKey(
        algorithm: params.EnforcedMlKemEncapsulateParams,
        decapsulationKey: MlKemPrivCryptoKey,
        ciphertext: BufferSource,
        sharedKeyAlgorithm: MlKemSharedKeyParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<MlKemSharedCryptoKeys> {
        return await WebCrypto.decapsulateKey<
            MlKemPrivCryptoKey,
            MlKemSharedCryptoKeys,
            params.EnforcedMlKemEncapsulateParams,
            MlKemSharedKeyParams
        >(
            algorithm,
            decapsulationKey,
            ciphertext,
            sharedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(sharedKeyAlgorithm.name)
        );
    }
}
