import * as alg from "../alg.js";
import * as params from "../params.js";
import { AesKey, AesShared } from "./shared.js";

export namespace AES_CBC {
    export async function generateKey(
        algorithm: Omit<params.EnforcedAesKeyGenParams, "name"> = {
            length: 256,
        },
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        return await AesShared.generateKey(
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
    ): Promise<AesKey> {
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
        keyData: AesKey,
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
        keyData: AesKey,
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
        wrappingkey: AesKey,
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
        unwrappingKey: AesKey,
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
