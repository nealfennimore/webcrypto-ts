/**
 * Code related to ECDH
 * @module
 */
import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";
import { Alg, EcdhCryptoKey, EcdhCryptoKeyPair, EcShared } from "./shared.js";

export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhCryptoKeyPair> =>
    await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    );

export const importKey = async (
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedEcKeyImportParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhCryptoKey> =>
    await EcShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    );

export const exportKey = EcShared.exportKey;

export async function deriveKey(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhCryptoKey,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<CryptoKey> {
    return await WebCrypto.deriveKey<
        CryptoKey,
        params.EnforcedAesKeyGenParams | params.EnforcedHmacKeyGenParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDH,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
    );
}

export async function deriveBits(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhCryptoKey,
    length: number
): Promise<ArrayBuffer> {
    return await WebCrypto.deriveBits<
        EcdhCryptoKey,
        params.EnforcedEcdhKeyDeriveParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDH,
        },
        baseKey,
        length
    );
}
