import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import * as params from "../params.js";
import { EcdsaCryptoKey, EcdsaCryptoKeyPair, SharedEc } from "./shared.js";

export namespace ECDSA {
    export const generateKey = async (
        algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
            namedCurve: alg.EC.Curve.P_521,
        },
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<EcdsaCryptoKeyPair> =>
        await SharedEc.generateKey(
            { ...algorithm, name: alg.EC.Variant.ECDSA },
            extractable,
            keyUsages
        );

    export const importKey = async (
        format: KeyFormat,
        keyData: BufferSource | JsonWebKey,
        algorithm: Omit<params.EnforcedEcKeyImportParams, "name"> = {
            namedCurve: alg.EC.Curve.P_521,
        },
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ): Promise<EcdsaCryptoKey> =>
        await SharedEc.importKey(
            format,
            keyData,
            { ...algorithm, name: alg.EC.Variant.ECDSA },
            extractable,
            keyUsages
        );

    export const exportKey = SharedEc.exportKey;

    export async function sign(
        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
        keyData: EcdsaCryptoKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign<EcdsaCryptoKey, params.EnforcedEcdsaParams>(
            {
                ...algorithm,
                name: alg.EC.Variant.ECDSA,
            },
            keyData,
            data
        );
    }

    export async function verify(
        algorithm: Omit<params.EnforcedEcdsaParams, "name">,
        keyData: EcdsaCryptoKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify<
            EcdsaCryptoKey,
            params.EnforcedEcdsaParams
        >(
            {
                ...algorithm,
                name: alg.EC.Variant.ECDSA,
            },
            keyData,
            signature,
            data
        );
    }
}
