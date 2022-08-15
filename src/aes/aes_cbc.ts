import * as alg from "../alg.js";
import * as params from "../params.js";
import { AesCbcCryptoKey, AesShared } from "./shared.js";

export namespace AES_CBC {
    export async function generateKey(
        algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
            length: 256,
        },
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesCbcCryptoKey> {
        return await AesShared.generateKey<AesCbcCryptoKey>(
            {
                ...algorithm,
                name: alg.AES.Mode.AES_CBC,
            },
            extractable,
            keyUsages
        );
    }

    export async function importKey(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.AesCbcKeyAlgorithm, "name">,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesCbcCryptoKey> {
        return await AesShared.importKey(
            format as any,
            keyData as any,
            {
                ...algorithm,
                name: alg.AES.Mode.AES_CBC,
            },
            extractable,
            keyUsages
        );
    }

    export const exportKey = AesShared.exportKey;

    export async function encrypt(
        algorithm: Omit<params.EnforcedAesCbcParams, "name">,
        keyData: AesCbcCryptoKey,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        return await AesShared.encrypt(
            {
                ...algorithm,
                name: alg.AES.Mode.AES_CBC,
            },
            keyData,
            plaintext
        );
    }

    export async function decrypt(
        algorithm: Omit<params.EnforcedAesCbcParams, "name">,
        keyData: AesCbcCryptoKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        return await AesShared.decrypt(
            {
                ...algorithm,
                name: alg.AES.Mode.AES_CBC,
            },
            keyData,
            ciphertext
        );
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesCbcCryptoKey,
        wrapAlgorithm: Omit<params.EnforcedAesCbcParams, "name">
    ): Promise<ArrayBuffer> {
        return await AesShared.wrapKey(format as any, key, wrappingkey, {
            ...wrapAlgorithm,
            name: alg.AES.Mode.AES_CBC,
        });
    }
    export async function unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: AesCbcCryptoKey,
        unwrappingKeyAlgorithm: Omit<params.EnforcedAesCbcParams, "name">,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        return await AesShared.unwrapKey(
            format,
            wrappedKey,
            wrappedKeyAlgorithm,
            unwrappingKey,
            {
                ...unwrappingKeyAlgorithm,
                name: alg.AES.Mode.AES_CBC,
            },
            extractable,
            keyUsages
        );
    }
}
