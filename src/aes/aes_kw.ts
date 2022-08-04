import * as alg from "../alg";
import * as params from "../params";
import { AesKey, AesShared } from "./shared";

export namespace AES_KW {
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
                name: alg.AES.Mode.AES_KW,
            },
            extractable,
            keyUsages
        );
    }

    export async function importKey(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        return await AesShared.importKey(
            format as any,
            keyData as any,
            {
                name: alg.AES.Mode.AES_KW,
            },
            extractable,
            keyUsages
        );
    }

    export const exportKey = AesShared.exportKey;

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesKey
    ): Promise<ArrayBuffer> {
        return await AesShared.wrapKey(format as any, key, wrappingkey, {
            name: alg.AES.Mode.AES_KW,
        });
    }
    export async function unwrapKey(
        format: KeyFormat,
        wrappedKey: BufferSource,
        wrappedKeyAlgorithm: params.EnforcedImportParams,
        unwrappingKey: AesKey,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        return await AesShared.unwrapKey(
            format,
            wrappedKey,
            wrappedKeyAlgorithm,
            unwrappingKey,
            {
                name: alg.AES.Mode.AES_KW,
            },
            extractable,
            keyUsages
        );
    }
}
