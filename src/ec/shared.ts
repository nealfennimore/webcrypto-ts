import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";

export interface EcKey extends CryptoKey {}
export interface EcKeyPair extends CryptoKeyPair {}

export namespace SharedEc {
    export async function generateKey(
        algorithm: params.EnforcedEcKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<EcKeyPair> {
        return await WebCrypto.generateKey<
            EcKeyPair,
            params.EnforcedEcKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: params.EnforcedEcKeyImportParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<EcKey> {
        return await WebCrypto.importKey<
            EcKey,
            params.EnforcedEcKeyImportParams
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
        keyData: EcKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }
}
