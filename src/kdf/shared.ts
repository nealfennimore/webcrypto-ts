import type { AesKey } from "../aes/index";
import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { HmacKey } from "../hmac/index";
import { DeriveKeyUsagePair, getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";

export interface Pbkdf2KeyMaterial extends CryptoKey {}
export interface HkdfKeyMaterial extends CryptoKey {}
export namespace KdfShared {
    export async function generateKeyMaterial<K extends CryptoKey>(
        format: KeyFormat,
        keyData: BufferSource,
        algorithm: alg.KDF.Variants,
        extractable: boolean = false
    ): Promise<K> {
        return await WebCrypto.importKey(
            format as any,
            keyData,
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
    ): Promise<AesKey | HmacKey> {
        return await WebCrypto.deriveKey<
            AesKey | HmacKey,
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
