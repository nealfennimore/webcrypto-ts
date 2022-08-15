import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    RsaPssCryptoKeyPair,
    RsaPssPrivCryptoKey,
    RsaPssPubCryptoKey,
    RsaShared,
} from "./shared.js";

export const generateKey = async (
    algorithm: Omit<params.EnforcedRsaHashedKeyGenParams, "name"> = {
        hash: SHA.Variant.SHA_512,
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
) =>
    (await RsaShared.generateKey(
        {
            ...algorithm,
            name: Alg.Variant.RSA_PSS,
        },
        extractable,
        keyUsages
    )) as RsaPssCryptoKeyPair;

export const importKey = async (
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<RsaPssPrivCryptoKey | RsaPssPubCryptoKey> =>
    await RsaShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.RSA_PSS },
        extractable,
        keyUsages
    );

export const exportKey = async (
    format: KeyFormat,
    keyData: RsaPssPrivCryptoKey | RsaPssPubCryptoKey
) => RsaShared.exportKey(format, keyData);

export const sign = async (
    saltLength: number,
    keyData: RsaPssPrivCryptoKey,
    data: BufferSource
) =>
    await RsaShared.sign(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        keyData,
        data
    );

export const verify = async (
    saltLength: number,
    keyData: RsaPssPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
) =>
    await RsaShared.verify(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        keyData,
        signature,
        data
    );
