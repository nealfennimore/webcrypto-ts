/**
 * Code related to ECDSA
 * @module
 */
import * as params from "../params.js";
import * as WebCrypto from "../webcrypto.js";
import {
    Alg,
    EcdsaCryptoKeyPair,
    EcdsaPrivCryptoKey,
    EcdsaPubCryptoKey,
    EcShared,
} from "./shared.js";

/**
 * Generate a new ECDSA keypair
 * @example
 * ```ts
 * const keyPair = await ECDSA.generateKey();
 * ```
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedEcKeyGenParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdsaCryptoKeyPair> =>
    await EcShared.generateKey(
        { ...algorithm, name: Alg.Variant.ECDSA },
        extractable,
        keyUsages
    );

/**
 * Import an ECDSA public or private key
 * @example
 * ```ts
 * const key = await ECDSA.importKey("jwk", pubKey, { namedCurve: "P-521" }, true, ['encrypt']);
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedEcKeyImportParams, "name"> = {
        namedCurve: Alg.Curve.P_521,
    },
    extractable?: boolean,
    keyUsages?: KeyUsage[]
): Promise<EcdsaPubCryptoKey | EcdsaPrivCryptoKey> =>
    await EcShared.importKey(
        format,
        keyData,
        { ...algorithm, name: Alg.Variant.ECDSA },
        extractable,
        keyUsages
    );

/**
 * Export an ECDSA public or private key
 * @example
 * ```ts
 * const pubKeyJwk = await ECDSA.importKey("jwk", keyPair.publicKey);
 * ```
 */
export const exportKey = async (
    format: KeyFormat,
    keyData: EcdsaPubCryptoKey | EcdsaPrivCryptoKey
) => EcShared.exportKey(format, keyData);

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await ECDSA.sign({hash: "SHA-512"}, keyPair.privateKey, message);
 * ```
 */
export async function sign(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    keyData: EcdsaPrivCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<EcdsaPrivCryptoKey, params.EnforcedEcdsaParams>(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
        },
        keyData,
        data
    );
}

/**
 * Verify a given signature
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const isVerified = await ECDSA.verify({hash: "SHA-512"}, keyPair.publicKey, signature, message);
 * ```
 */
export async function verify(
    algorithm: Omit<params.EnforcedEcdsaParams, "name">,
    keyData: EcdsaPubCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await WebCrypto.verify<
        EcdsaPubCryptoKey,
        params.EnforcedEcdsaParams
    >(
        {
            ...algorithm,
            name: Alg.Variant.ECDSA,
        },
        keyData,
        signature,
        data
    );
}
