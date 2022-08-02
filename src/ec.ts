import { KeyUsagePairs, getKeyUsagePairsByAlg } from "./keyUsages";
import * as params from "./params";
import * as alg from "./alg";
import { WebCrypto } from "./crypto";

export interface EcKey extends CryptoKey {}
export interface EcPubKey extends CryptoKey {}
export interface EcPrivKey extends CryptoKey {}
export interface EcKeyPair extends CryptoKeyPair {}

export namespace EC {
    export async function generateKey(
        algorithm: params.EnforcedEcKeyGenParams,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<EcKey | EcKeyPair> {
        return await WebCrypto.generateKey<
            EcKey | EcKeyPair,
            params.EnforcedEcKeyGenParams
        >(
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function importKey(
        format: KeyFormat,
        algorithm: params.EnforcedEcKeyImportParams,
        keyData: BufferSource | JsonWebKey,
        extractable: boolean = true,
        keyUsages?: KeyUsage[]
    ): Promise<EcKey> {
        return await WebCrypto.importKey<
            EcKey,
            params.EnforcedEcKeyImportParams
        >(
            format as any,
            keyData as any,
            algorithm,
            extractable,
            keyUsages ?? getKeyUsagePairsByAlg(algorithm.name)
        );
    }

    export async function exportKey(
        format: KeyFormat,
        keyData: EcKey
    ): Promise<JsonWebKey | ArrayBuffer> {
        return await WebCrypto.exportKey(format as any, keyData);
    }
}

export namespace ECDSA {
    export const generateKey = async (
        namedCurve: alg.EC.Curves,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await EC.generateKey(
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
        await EC.importKey(
            format,
            { name: alg.EC.Variant.ECDSA, namedCurve },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = EC.exportKey;

    export async function sign(
        algorithm: params.EnforcedEcdsaParams,
        keyData: EcKey,
        data: BufferSource
    ): Promise<ArrayBuffer> {
        return await WebCrypto.sign(algorithm, keyData, data);
    }

    export async function verify(
        algorithm: params.EnforcedEcdsaParams,
        keyData: EcKey,
        signature: BufferSource,
        data: BufferSource
    ): Promise<boolean> {
        return await WebCrypto.verify(algorithm, keyData, signature, data);
    }
}

export namespace ECDH {
    export const generateKey = async (
        namedCurve: alg.EC.Curves,
        extractable?: boolean,
        keyUsages?: KeyUsage[]
    ) =>
        await EC.generateKey(
            { name: alg.EC.Variant.ECDH, namedCurve },
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
        await EC.importKey(
            format,
            { name: alg.EC.Variant.ECDH, namedCurve },
            keyData,
            extractable,
            keyUsages
        );

    export const exportKey = EC.exportKey;

    export async function deriveKey(
        publicKey: EcPubKey,
        baseKey: EcPrivKey,
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
        publicKey: EcPubKey,
        baseKey: EcPrivKey,
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
