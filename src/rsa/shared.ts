import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";

export interface RsaKey extends CryptoKey {}
export interface RsaKeyPair extends CryptoKeyPair {}

export namespace RsaShared {
    export async function generateKey(
        algorithm: params.EnforcedRsaHashedKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<RsaKey | RsaKeyPair> {
        return await WebCrypto.generateKey<
            RsaKey | RsaKeyPair,
            params.EnforcedRsaHashedKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: KeyFormat,
        algorithm: params.EnforcedRsaHashedImportParams,
        keyData: BufferSource | JsonWebKey,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<RsaKey> {
        return await WebCrypto.importKey<
            RsaKey,
            params.EnforcedRsaHashedImportParams
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
        keyData: RsaKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function sign(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(algorithm, keyData, data);
    }

    export async function verify(
        algorithm:
            | params.EnforcedRsaPssParams
            | params.EnforcedRsassaPkcs1v15Params,
        keyData: RsaKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(algorithm, keyData, signature, data);
    }
}
