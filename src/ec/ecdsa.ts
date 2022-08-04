import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import * as params from "../params";
import { EcKey, SharedEc } from "./shared";

export namespace ECDSA {
    export const generateKey = async (
        algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
            namedCurve: alg.EC.Curve.P_521,
        },
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
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
    ) =>
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
        keyData: EcKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign<EcKey, params.EnforcedEcdsaParams>(
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
        keyData: EcKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify<EcKey, params.EnforcedEcdsaParams>(
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
