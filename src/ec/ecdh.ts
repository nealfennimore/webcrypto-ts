/**
 * Code related to ECDH
 * @module
 */
import { AesCryptoKeys } from "../aes/shared.js";
import { HmacCryptoKey } from "../hmac/index.js";
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    EcdhCryptoKeyPair,
    EcdhPrivCryptoKey,
    EcdhPubCryptoKey,
    EcShared,
} from "./shared.js";

/**
 * Generate a new ECDH keypair
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * ```
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhCryptoKeyPair> =>
    await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    );

/**
 * Import an ECDH public or private key
 * @example
 * ```ts
 * const key = await ECDH.importKey("jwk", pubKey, { namedCurve: "P-521" }, true, ['deriveKey', 'deriveBits']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedEcKeyImportParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdhPubCryptoKey | EcdhPrivCryptoKey> =>
    await EcShared.importKey(
        format,
        key,
        { ...algorithm, name: Alg.Variant.ECDH },
        extractable,
        keyUsages
    );

/**
 * Export an ECDH public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await ECDH.importKey("jwk", keyPair.publicKey);
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    key: EcdhPubCryptoKey | EcdhPrivCryptoKey
) => EcShared.exportKey(format, key);

/**
 * Derive a shared key between two ECDH key pairs
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const hmacParams: params.EnforcedHmacKeyGenParams = {
 *      name: Authentication.Alg.Code.HMAC,
 *      hash: SHA.Alg.Variant.SHA_512,
 *      length: 512,
 * };
 * let key = await ECDH.deriveKey(
 *      { public: otherKeyPair.publicKey },
 *      keyPair.privateKey,
 *      hmacParams
 * );
 * ```
 */
export async function deriveKey(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhPrivCryptoKey,
    derivedKeyType:
        | params.EnforcedAesKeyGenParams
        | params.EnforcedHmacKeyGenParams,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<HmacCryptoKey | AesCryptoKeys> {
    return await WebCrypto.deriveKey<
        HmacCryptoKey | AesCryptoKeys,
        params.EnforcedAesKeyGenParams | params.EnforcedHmacKeyGenParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDH,
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(derivedKeyType.name)
    );
}

/**
 * Derive a shared bits between two ECDH key pairs
 * @example
 * ```ts
 * const keyPair = await ECDH.generateKey();
 * const otherKeyPair = await ECDH.generateKey();
 * const bits = await ECDH.deriveBits(
 *      { public: otherKeyPair.publicKey },
 *      keyPair.privateKey,
 *      128
 * );
 * ```
 */
export async function deriveBits(
    algorithm: Omit<params.EnforcedEcdhKeyDeriveParams, "name">,
    baseKey: EcdhPrivCryptoKey,
    length: number
): Promise<ArrayBuffer> {
    return await WebCrypto.deriveBits<
        EcdhPrivCryptoKey,
        params.EnforcedEcdhKeyDeriveParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDH,
        },
        baseKey,
        length
    );
}
