import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";

export interface AesKey extends CryptoKey {}

export namespace AesShared {
    export async function generateKey(
        algorithm: params.EnforcedAesKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        return await WebCrypto.generateKey<
            AesKey,
            params.EnforcedAesKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: params.EnforcedAesKeyAlgorithms,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        return await WebCrypto.importKey<
            AesKey,
            params.EnforcedAesKeyAlgorithms
        >(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        keyData: AesKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function encrypt(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        keyData: AesKey,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.encrypt(algorithm, keyData, plaintext);
    }

    export async function decrypt(
        algorithm: Exclude<
            params.EnforcedAesParams,
            params.EnforcedAesKwParams
        >,
        keyData: AesKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.decrypt(algorithm, keyData, ciphertext);
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesKey,
        wrapAlgorithm: params.EnforcedAesParams
    ): Promise<ArrayBuffer> {
        return await WebCrypto.wrapKey(
            format as any,
            key,
            wrappingkey,
            wrapAlgorithm
        );
    }
    export async function unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: AesKey,
        unwrappingKeyAlgorithm: params.EnforcedAesParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        return await WebCrypto.unwrapKey(
            format as any,
            wrappedKey,
            unwrappingKey,
            unwrappingKeyAlgorithm,
            wrappedKeyAlgorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(wrappedKeyAlgorithm.name)
        );
    }
}
