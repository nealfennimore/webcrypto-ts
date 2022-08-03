import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";
import { AesKey, AesShared } from "./shared";

export namespace AES_CTR {
    export async function generateCounter(
        counterLength: number = 8
    ): Promise<Uint8Array> {
        const nonce = await WebCrypto._crypto.getRandomValues(
            new Uint8Array(16 - counterLength)
        );
        const counter = new Uint8Array(16);
        counter.set([1], 15);
        counter.set(nonce);
        return counter;
    }
    export async function generateKey(
        length: params.EnforcedAesKeyGenParams["length"] = 256,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const _algorithm: params.EnforcedAesKeyGenParams = {
            name: alg.AES.Mode.AES_CTR,
            length,
        };
        return await AesShared.generateKey(_algorithm, extractable, keyUsages);
    }

    export async function importKey(
        format: KeyFormat,
        length: params.AesCtrKeyAlgorithm["length"],
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<AesKey> {
        const algorithm: params.AesCtrKeyAlgorithm = {
            name: alg.AES.Mode.AES_CTR,
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
        algorithm: Omit<params.EnforcedAesCtrParams, "name">,
        keyData: AesKey,
        plaintext: BufferSource
    ): Promise<ArrayBuffer> {
        const _algorithm: params.EnforcedAesCtrParams = {
            ...algorithm,
            name: alg.AES.Mode.AES_CTR,
        };
        return await AesShared.encrypt(_algorithm, keyData, plaintext);
    }

    export async function decrypt(
        algorithm: Omit<params.EnforcedAesCtrParams, "name">,
        keyData: AesKey,
        ciphertext: BufferSource
    ): Promise<ArrayBuffer> {
        const _algorithm: params.EnforcedAesCtrParams = {
            ...algorithm,
            name: alg.AES.Mode.AES_CTR,
        };
        return await AesShared.decrypt(_algorithm, keyData, ciphertext);
    }

    export async function wrapKey(
        format: KeyFormat,
        key: CryptoKey,
        wrappingkey: AesKey,
        wrapAlgorithm: Omit<params.EnforcedAesCtrParams, "name">
    ): Promise<ArrayBuffer> {
        const _wrapAlgorithm: params.EnforcedAesCtrParams = {
            ...wrapAlgorithm,
            name: alg.AES.Mode.AES_CTR,
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
        unwrappingKeyAlgorithm: Omit<params.EnforcedAesCtrParams, "name">,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<CryptoKey> {
        const _unwrappingKeyAlgorithm: params.EnforcedAesCtrParams = {
            ...unwrappingKeyAlgorithm,
            name: alg.AES.Mode.AES_CTR,
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
