import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    RsaShared,
    RsassaPkcs1V15CryptoKeyPair,
    RsassaPkcs1V15PrivCryptoKey,
    RsassaPkcs1V15PubCryptoKey,
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
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        extractable,
        keyUsages
    )) as RsassaPkcs1V15CryptoKeyPair;

export const importKey = async (
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<RsassaPkcs1V15PubCryptoKey | RsassaPkcs1V15PrivCryptoKey> =>
    await RsaShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.RSASSA_PKCS1_v1_5 },
        extractable,
        keyUsages
    );

export const exportKey = async (
    format: KeyFormat,
    keyData: RsassaPkcs1V15PubCryptoKey | RsassaPkcs1V15PrivCryptoKey
) => RsaShared.exportKey(format, keyData);

export const sign = async (
    keyData: RsassaPkcs1V15PrivCryptoKey,
    data: BufferSource
) =>
    await RsaShared.sign(
        {
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        keyData,
        data
    );

export const verify = async (
    keyData: RsassaPkcs1V15PubCryptoKey,
    signature: BufferSource,
    data: BufferSource
) =>
    await RsaShared.verify(
        {
            name: Alg.Variant.RSASSA_PKCS1_v1_5,
        },
        keyData,
        signature,
        data
    );
