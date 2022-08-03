import * as alg from "../alg";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";
import { AesKey, AesShared } from "./shared";

export namespace AES_KW {
    export async function generateKey(
        length: params.EnforcedAesKeyGenParams["length"],
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const _algorithm: params.EnforcedAesKeyGenParams = {
            name: alg.AES.Mode.AES_KW,
            length,
        };
        return await AesShared.generateKey(_algorithm, extractable, keyUsages);
    }

    export async function importKey(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const algorithm: params.AesKwKeyAlgorithm = {
            name: alg.AES.Mode.AES_KW,
        };

        return await AesShared.importKey(
            format as any,
            algorithm,
            keyData as any,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export const exportKey = AesShared.exportKey;

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesKey
    ): Promise<ArrayBuffer> {
        const wrapAlgorithm: params.EnforcedAesKwParams = {
            name: alg.AES.Mode.AES_KW,
        };
        return await AesShared.wrapKey(
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
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        const unwrappingKeyAlgorithm: params.EnforcedAesKwParams = {
            name: alg.AES.Mode.AES_KW,
        };
        return await AesShared.unwrapKey(
            format,
            wrappedKey,
            wrappedKeyAlgorithm,
            unwrappingKey,
            unwrappingKeyAlgorithm,
            extractable,
            keyUsages
        );
    }
}
