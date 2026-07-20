/**
 * Shared code for ML-DSA. Requires Node.js 24.7.0 or higher.
 * @module
 */
import {
    ExtendedKeyFormat,
    ExtendedKeyUsage,
    getKeyUsagePairsByAlg,
} from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface MlDsaPubCryptoKey extends CryptoKey {
    _mlDsaPubCryptoKeyBrand: any;
}
export interface MlDsaPrivCryptoKey extends CryptoKey {
    _mlDsaPrivCryptoKeyBrand: any;
}
export interface MlDsaCryptoKeyPair extends CryptoKeyPair {
    _mlDsaCryptoKeyPairBrand: any;
    publicKey: MlDsaPubCryptoKey;
    privateKey: MlDsaPrivCryptoKey;
}

export interface MlDsaProxiedPubCryptoKey
    extends proxy.ProxiedCryptoKey<MlDsaPubCryptoKey> {
    verify: (
        signature: BufferSource,
        data: BufferSource,
        algorithm?: Omit<params.EnforcedMlDsaSignParams, "name">
    ) => Promise<boolean>;

    exportKey: (
        format: ExtendedKeyFormat
    ) => Promise<JsonWebKey | ArrayBuffer>;
}
export interface MlDsaProxiedPrivCryptoKey
    extends proxy.ProxiedCryptoKey<MlDsaPrivCryptoKey> {
    sign: (
        data: BufferSource,
        algorithm?: Omit<params.EnforcedMlDsaSignParams, "name">
    ) => Promise<ArrayBuffer>;

    exportKey: (
        format: ExtendedKeyFormat
    ) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface MlDsaProxiedCryptoKeyPair
    extends proxy.ProxiedCryptoKeyPair<
        MlDsaCryptoKeyPair,
        MlDsaPrivCryptoKey,
        MlDsaProxiedPrivCryptoKey,
        MlDsaPubCryptoKey,
        MlDsaProxiedPubCryptoKey
    > {}

export type MlDsaCryptoKeys = MlDsaPubCryptoKey | MlDsaPrivCryptoKey;

export namespace Alg {
    export enum Variant {
        ML_DSA_44 = "ML-DSA-44",
        ML_DSA_65 = "ML-DSA-65",
        ML_DSA_87 = "ML-DSA-87",
    }
    export type Variants = `${Variant}`;
}

export namespace MlDsaShared {
    export async function generateKey(
        algorithm: params.EnforcedMlDsaKeyGenParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<MlDsaCryptoKeyPair> {
        return await WebCrypto.generateKey<
            MlDsaCryptoKeyPair,
            params.EnforcedMlDsaKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: ExtendedKeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedMlDsaImportParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<MlDsaCryptoKeys> {
        return await WebCrypto.importKey<
            MlDsaCryptoKeys,
            params.EnforcedMlDsaImportParams
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
        key: MlDsaCryptoKeys
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format, key);
    }

    export async function sign(
        algorithm: params.EnforcedMlDsaSignParams,
        key: MlDsaPrivCryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign<
            MlDsaPrivCryptoKey,
            params.EnforcedMlDsaSignParams
        >(algorithm, key, data);
    }

    export async function verify(
        algorithm: params.EnforcedMlDsaSignParams,
        key: MlDsaPubCryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify<
            MlDsaPubCryptoKey,
            params.EnforcedMlDsaSignParams
        >(algorithm, key, signature, data);
    }
}
