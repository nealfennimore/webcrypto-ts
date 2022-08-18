/**
 * Code related to RSA_PSS
 * @module
 */

import * as params from "../params.js";
import { Alg as SHA } from "../sha/shared.js";
import {
    Alg,
    RsaPssCryptoKeyPair,
    RsaPssPrivCryptoKey,
    RsaPssPubCryptoKey,
    RsaShared,
} from "./shared.js";

/**
 * Generate a new RSA_PSS keypair
 * @example
 * ```ts
 * const keyPair = await RSA_PSS.generateKey();
 * ```
 */
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

/**
 * Import an RSA_PSS public or private key
 * @example
 * ```ts
 * const key = await RSA_PSS.importKey("jwk", pubKey, { hash: "SHA-512" }, true, ['verify']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedRsaHashedImportParams, "name">,
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<RsaPssPrivCryptoKey | RsaPssPubCryptoKey> =>
    await RsaShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.RSA_PSS },
        extractable,
        keyUsages
    );

/**
 * Export an RSA_PSS public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await RSA_PSS.importKey("jwk", keyPair.publicKey);
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: RsaPssPrivCryptoKey | RsaPssPubCryptoKey
) => RsaShared.exportKey(format, key);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await RSA_PSS.sign(128, keyPair.privateKey, message);
 * ```
 */
export const sign = async (
    saltLength: number,
    key: RsaPssPrivCryptoKey,
    data: BufferSource
) =>
    await RsaShared.sign(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        key,
        data
    );

/**
 * Verify a given signature
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await ECDSA.verify(128, keyPair.publicKey, signature, message);
 * ```
 */
export const verify = async (
    saltLength: number,
    key: RsaPssPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
) =>
    await RsaShared.verify(
        {
            name: Alg.Variant.RSA_PSS,
            saltLength,
        },
        key,
        signature,
        data
    );
