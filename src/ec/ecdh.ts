import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { getKeyUsagePairsByAlg } from "../keyUsages";
import * as params from "../params";
import { EcKey, EcKeyPair, SharedEc } from "./shared";

export namespace ECDH {
    export const generateKey = async (
        namedCurve: alg.EC.Curves = alg.EC.Curve.P_521,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        (await SharedEc.generateKey(
            { name: alg.EC.Variant.ECDH, namedCurve },
            extractable,
            keyUsages
        )) as EcKeyPair;

    export const importKey = async (
        format: KeyFormat,
        namedCurve: alg.EC.Curves,
        keyData: BufferSource | JsonWebKey,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await SharedEc.importKey(
            format,
            { name: alg.EC.Variant.ECDH, namedCurve },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = SharedEc.exportKey;

    export async function deriveKey(
        publicKey: EcKey,
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
                name: alg.EC.Variant.ECDH,
                public: publicKey,
            },
            baseKey,
            derivedKeyType,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
        );
    }

    export async function deriveBits(
        publicKey: EcKey,
        baseKey: EcKey,
        length: number
    ): Promise<ArrayBuffer> {
        return await WebCrypto.deriveBits(
            {
                name: alg.EC.Variant.ECDH,
                public: publicKey,
            },
            baseKey,
            length
        );
    }
}
