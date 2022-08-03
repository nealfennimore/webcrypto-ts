import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import * as params from "../params";
import { EcKey, SharedEc } from "./shared";

export namespace ECDSA {
    export const generateKey = async (
        namedCurve: alg.EC.Curves = alg.EC.Curve.P_521,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await SharedEc.generateKey(
            { name: alg.EC.Variant.ECDSA, namedCurve },
            extractable,
            keyUsages
        );

    export const importKey = async (
        format: KeyFormat,
        namedCurve: alg.EC.Curves,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await SharedEc.importKey(
            format,
            { name: alg.EC.Variant.ECDSA, namedCurve },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = SharedEc.exportKey;

    export async function sign(
        hash: params.EnforcedEcdsaParams["hash"],
        keyData: EcKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(
            {
                name: alg.EC.Variant.ECDSA,
                hash,
            },
            keyData,
            data
        );
    }

    export async function verify(
        hash: params.EnforcedEcdsaParams["hash"],
        keyData: EcKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(
            {
                name: alg.EC.Variant.ECDSA,
                hash,
            },
            keyData,
            signature,
            data
        );
    }
}
