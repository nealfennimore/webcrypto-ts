import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { getKeyUsagePairsByAlg } from "../keyUsages.js";
import * as params from "../params.js";
import { EcKey, EcKeyPair, SharedEc } from "./shared.js";

export namespace ECDH {
    export const generateKey = async (
        algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
            namedCurve: alg.EC.Curve.P_521,
        },
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        (await SharedEc.generateKey(
            { ...algorithm, name: alg.EC.Variant.ECDH },
            extractable,
            keyUsages
        )) as EcKeyPair;

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
            { ...algorithm, name: alg.EC.Variant.ECDH },
            extractable,
            keyUsages
        );

    export const exportKey = SharedEc.exportKey;

    export async function deriveKey(
        algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
        baseKey: EcKey,
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
                name: alg.EC.Variant.ECDH,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
        );
    }

    export async function deriveBits(
        algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
        baseKey: EcKey,
        length: number
    ): Promise<ArrayBuffer> {
        return await WebCrypto.deriveBits<
            EcKey,
            params.EnforcedEcdhKeyDeriveParams
        >(
            {
                ...algorithm,
                name: alg.EC.Variant.ECDH,
            },
            baseKey,
            length
        );
    }
}
