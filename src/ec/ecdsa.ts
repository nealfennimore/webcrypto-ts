/**
 * Code related to ECDSA
 */
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    EcdsaCryptoKeyPair,
    EcdsaPrivCryptoKey,
    EcdsaPubCryptoKey,
    EcShared,
} from "./shared.js";

export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdsaCryptoKeyPair> =>
    await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDSA },
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
): Promise<EcdsaPubCryptoKey | EcdsaPrivCryptoKey> =>
    await EcShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.ECDSA },
        extractable,
        keyUsages
    );

export const exportKey = EcShared.exportKey;

export async function sign(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    keyData: EcdsaPrivCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<EcdsaPrivCryptoKey, params.EnforcedEcdsaParams>(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
        },
        keyData,
        data
    );
}

export async function verify(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    keyData: EcdsaPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await WebCrypto.verify<
        EcdsaPubCryptoKey,
        params.EnforcedEcdsaParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
        },
        keyData,
        signature,
        data
    );
}
