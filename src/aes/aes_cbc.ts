import * as alg from "../alg";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";
import { AesKey, AesShared } from "./shared";

export namespace AES_CBC {
    export async function generateKey(
        length: params.EnforcedAesKeyGenParams["length"] = 256,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const _algorithm: params.EnforcedAesKeyGenParams = {
            name: alg.AES.Mode.AES_CBC,
            length,
        };
        return await AesShared.generateKey(_algorithm, extractable, keyUsages);
    }

    export async function importKey(
        format: KeyFormat,
        length: params.AesCbcKeyAlgorithm["length"],
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const algorithm: params.AesCbcKeyAlgorithm = {
            name: alg.AES.Mode.AES_CBC,
            length,
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

    export async function encrypt(
        algorithm: Omit<params.EnforcedAesCbcParams, "name">,
        keyData: AesKey,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        const _algorithm: params.EnforcedAesCbcParams = {
            ...algorithm,
            name: alg.AES.Mode.AES_CBC,
        };
        return await AesShared.encrypt(_algorithm, keyData, plaintext);
    }

    export async function decrypt(
        algorithm: Omit<params.EnforcedAesCbcParams, "name">,
        keyData: AesKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        const _algorithm: params.EnforcedAesCbcParams = {
            ...algorithm,
            name: alg.AES.Mode.AES_CBC,
        };
        return await AesShared.decrypt(_algorithm, keyData, ciphertext);
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesKey,
        wrapAlgorithm: Omit<params.EnforcedAesCbcParams, "name">
    ): Promise<ArrayBuffer> {
        const _wrapAlgorithm: params.EnforcedAesCbcParams = {
            ...wrapAlgorithm,
            name: alg.AES.Mode.AES_CBC,
        };
        return await AesShared.wrapKey(
            format as any,
            key,
            wrappingkey,
            _wrapAlgorithm
        );
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
        const _unwrappingKeyAlgorithm: params.EnforcedAesCbcParams = {
            ...unwrappingKeyAlgorithm,
            name: alg.AES.Mode.AES_CBC,
        };
        return await AesShared.unwrapKey(
            format,
            wrappedKey,
            wrappedKeyAlgorithm,
            unwrappingKey,
            _unwrappingKeyAlgorithm,
            extractable,
            keyUsages
        );
    }
}
