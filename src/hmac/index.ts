import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";
export interface HmacKey extends CryptoKey {}

export namespace HMAC {
    export const generateKey = async (
        hash: params.EnforcedHmacKeyGenParams["hash"] = alg.SHA.Variant.SHA_512,
        length?: params.EnforcedHmacKeyGenParams["length"],
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ) =>
        await WebCrypto.generateKey<HmacKey, params.EnforcedHmacKeyGenParams>(
            {
                name: alg.Authentication.Code.HMAC,
                hash,
                length,
            },
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(alg.Authentication.Code.HMAC)
        );

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        hash: params.EnforcedHmacImportParams["hash"],
        length?: params.EnforcedHmacImportParams["length"],
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ) =>
        await WebCrypto.importKey<HmacKey, params.EnforcedHmacImportParams>(
            format as any,
            keyData as any,
            { name: alg.Authentication.Code.HMAC, hash, length },
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(alg.Authentication.Code.HMAC)
        );

    export async function exportKey(
        format: KeyFormat,
        keyData: HmacKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }

    export async function sign(
        keyData: HmacKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(
            {
                name: alg.Authentication.Code.HMAC,
            },
            keyData,
            data
        );
    }

    export async function verify(
        keyData: HmacKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(
            {
                name: alg.Authentication.Code.HMAC,
            },
            keyData,
            signature,
            data
        );
    }
}
