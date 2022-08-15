import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
export interface HmacCryptoKey extends CryptoKey {
    _hmacKeyBrand: any;
}

export namespace HMAC {
    export const generateKey = async (
        algorithm: Omit<params.EnforcedHmacKeyGenParams, "name"> = {
            hash: alg.SHA.Variant.SHA_512,
        },
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ) =>
        await WebCrypto.generateKey<
            HmacCryptoKey,
            params.EnforcedHmacKeyGenParams
        >(
            {
                ...algorithm,
                name: alg.Authentication.Code.HMAC,
            },
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(alg.Authentication.Code.HMAC)
        );

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.EnforcedHmacImportParams, "name">,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ) =>
        await WebCrypto.importKey<
            HmacCryptoKey,
            params.EnforcedHmacImportParams
        >(
            format as any,
            keyData as any,
            { ...algorithm, name: alg.Authentication.Code.HMAC },
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(alg.Authentication.Code.HMAC)
        );

    export async function exportKey(
        format: KeyFormat,
        keyData: HmacCryptoKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey<HmacCryptoKey>(format as any, keyData);
    }

    export async function sign(
        keyData: HmacCryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign<HmacCryptoKey, params.HmacKeyAlgorithm>(
            {
                name: alg.Authentication.Code.HMAC,
            },
            keyData,
            data
        );
    }

    export async function verify(
        keyData: HmacCryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify<HmacCryptoKey, params.HmacKeyAlgorithm>(
            {
                name: alg.Authentication.Code.HMAC,
            },
            keyData,
            signature,
            data
        );
    }
}
