/**
 * Code related to HMAC
 * @module
 */
import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import * as WebCrypto from "../webcrypto.js";
export interface HmacCryptoKey extends CryptoKey {
    _hmacKeyBrand: any;
}

export namespace Alg {
    export enum Code {
        HMAC = "HMAC",
    }
    export type Codes = `${Code}`;
}

export const generateKey = async (
    algorithm: Omit<params.EnforcedHmacKeyGenParams, "name"> = {
        hash: SHA.Variant.SHA_512,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
) =>
    await WebCrypto.generateKey<HmacCryptoKey, params.EnforcedHmacKeyGenParams>(
        {
            ...algorithm,
            name: Alg.Code.HMAC,
        },
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(Alg.Code.HMAC)
    );

export const importKey = async (
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedHmacImportParams, "name">,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
) =>
    await WebCrypto.importKey<HmacCryptoKey, params.EnforcedHmacImportParams>(
        format as any,
        keyData as any,
        { ...algorithm, name: Alg.Code.HMAC },
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(Alg.Code.HMAC)
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
            name: Alg.Code.HMAC,
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
            name: Alg.Code.HMAC,
        },
        keyData,
        signature,
        data
    );
}
