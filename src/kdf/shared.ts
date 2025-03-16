/**
 * Shared code for KDF
 * @module
 */
import type { AesCryptoKeys } from "../aes/index.js";
import { AesProxiedCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey, HmacProxiedCryptoKey } from "../hmac/index.js";
import { DeriveKeyUsagePair, getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import * as WebCrypto from "../webcrypto.js";

export interface Pbkdf2KeyMaterial extends CryptoKey {
    _pbkdf2KeyMaterialBrand: any;
}
export interface HkdfKeyMaterial extends CryptoKey {
    _kkdfKeyMaterialBrand: any;
}

export namespace Alg {
    export enum Variant {
        PBKDF2 = "PBKDF2",
        HKDF = "HKDF",
    }
    export type Variants = `${Variant}`;
}

export namespace KdfShared {
    export async function generateKeyMaterial<K extends CryptoKey>(
        format: KeyFormat,
        key: BufferSource,
        algorithm: Alg.Variants,
        extractable: boolean = false
    ): Promise<K> {
        return await WebCrypto.importKey(
            format as any,
            key,
            algorithm,
            extractable,
            DeriveKeyUsagePair
        );
    }

    export async function deriveKey(
        algorithm: params.EnforcedPbkdf2Params | params.EnforcedHkdfParams,
        baseKey: Pbkdf2KeyMaterial | HkdfKeyMaterial,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesCryptoKeys | HmacCryptoKey> {
        return await WebCrypto.deriveKey<
            AesCryptoKeys | HmacCryptoKey,
            params.EnforcedAesKeyGenParams | params.EnforcedHmacKeyGenParams
        >(
            algorithm,
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
        );
    }

    export async function deriveBits(
        algorithm: params.EnforcedPbkdf2Params | params.EnforcedHkdfParams,
        baseKey: Pbkdf2KeyMaterial | HkdfKeyMaterial,
        length: number
    ): Promise<ArrayBuffer> {
        return await WebCrypto.deriveBits(algorithm, baseKey, length);
    }
}

export interface HkdfProxiedKeyMaterial
    extends proxy.ProxiedCryptoKey<HkdfKeyMaterial> {
    deriveKey(
        algorithm: Omit<params.EnforcedHkdfParams, "name">,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesProxiedCryptoKeys | HmacProxiedCryptoKey>;

    deriveBits(
        algorithm: Omit<params.EnforcedHkdfParams, "name">,
        length: number
    ): Promise<ArrayBuffer>;
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

export interface Pbkdf2ProxiedKeyMaterial
    extends proxy.ProxiedCryptoKey<Pbkdf2KeyMaterial> {
    deriveKey(
        algorithm: Omit<params.EnforcedPbkdf2Params, "name" | "iterations">,
        derivedKeyType:
            | params.EnforcedAesKeyGenParams
            | params.EnforcedHmacKeyGenParams,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesProxiedCryptoKeys | HmacProxiedCryptoKey>;
    deriveBits(
        algorithm: Omit<params.EnforcedPbkdf2Params, "name" | "iterations">,
        length: number
    ): Promise<ArrayBuffer>;
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}
