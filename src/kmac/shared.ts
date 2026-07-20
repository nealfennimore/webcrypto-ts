/**
 * Shared code for KMAC. Requires Node.js 24.8.0 or higher.
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

export interface KmacCryptoKey extends CryptoKey {
    _kmacKeyBrand: any;
}
export interface KmacProxiedCryptoKey
    extends proxy.ProxiedCryptoKey<KmacCryptoKey> {
    sign: (
        algorithm: Omit<params.EnforcedKmacParams, "name">,
        data: BufferSource
    ) => Promise<ArrayBuffer>;
    verify: (
        algorithm: Omit<params.EnforcedKmacParams, "name">,
        signature: BufferSource,
        data: BufferSource
    ) => Promise<boolean>;
    exportKey: (
        format: ExtendedKeyFormat
    ) => Promise<JsonWebKey | ArrayBuffer>;
}

export namespace Alg {
    export enum Code {
        KMAC128 = "KMAC128",
        KMAC256 = "KMAC256",
    }
    export type Codes = `${Code}`;
}

export namespace KmacShared {
    export async function generateKey(
        algorithm: params.EnforcedKmacKeyGenParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<KmacCryptoKey> {
        return await WebCrypto.generateKey<
            KmacCryptoKey,
            params.EnforcedKmacKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: ExtendedKeyFormat,
        key: BufferSource | JsonWebKey,
        algorithm: params.EnforcedKmacImportParams,
        extractable: boolean = true,
        keyUsages?: ExtendedKeyUsage[]
    ): Promise<KmacCryptoKey> {
        return await WebCrypto.importKey<
            KmacCryptoKey,
            params.EnforcedKmacImportParams
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
        key: KmacCryptoKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format, key);
    }

    export async function sign(
        algorithm: params.EnforcedKmacParams,
        key: KmacCryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(
            // `length` mirrors `outputLength` for Node.js 24.8.0 through
            // 24.14.x, which used the pre-rename member name.
            {
                ...algorithm,
                length: algorithm.outputLength,
            },
            key,
            data
        );
    }

    export async function verify(
        algorithm: params.EnforcedKmacParams,
        key: KmacCryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(
            {
                ...algorithm,
                length: algorithm.outputLength,
            },
            key,
            signature,
            data
        );
    }
}
