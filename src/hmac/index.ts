/**
 * Code related to HMAC
 * @module
 */
import { getKeyUsagePairsByAlg } from "../key_usages.js";
import * as params from "../params.js";
import * as proxy from "../proxy.js";
import { Alg as SHA } from "../sha/shared.js";
import * as WebCrypto from "../webcrypto.js";

export interface HmacCryptoKey extends CryptoKey {
    _hmacKeyBrand: any;
}
export interface HmacProxiedCryptoKey
    extends proxy.ProxiedCryptoKey<HmacCryptoKey> {
    sign: (data: BufferSource) => Promise<ArrayBuffer>;
    verify: (signature: BufferSource, data: BufferSource) => Promise<boolean>;
    exportKey: (format: KeyFormat) => Promise<JsonWebKey | ArrayBuffer>;
}

const handler: ProxyHandler<HmacCryptoKey> = {
    get(target: HmacCryptoKey, prop: string) {
        switch (prop) {
            case "self":
                return target;
            case "sign":
                return (data: BufferSource) => sign(target, data);
            case "verify":
                return (signature: BufferSource, data: BufferSource) =>
                    verify(target, signature, data);
            case "exportKey":
                return (format: KeyFormat) => exportKey(format, target);
        }

        return Reflect.get(target, prop);
    },
};

export namespace Alg {
    export enum Code {
        HMAC = "HMAC",
    }
    export type Codes = `${Code}`;
}

/**
 * Generate a new HMAC key
 * @example
 * ```ts
 * const key = await HMAC.generateKey();
 * ```
 */
export const generateKey = async (
    algorithm: Omit<params.EnforcedHmacKeyGenParams, "name"> = {
        hash: SHA.Variant.SHA_512,
    },
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<proxy.ProxiedCryptoKey<HmacCryptoKey>> => {
    const key = await WebCrypto.generateKey<
        HmacCryptoKey,
        params.EnforcedHmacKeyGenParams
    >(
        {
            ...algorithm,
            name: Alg.Code.HMAC,
        },
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(Alg.Code.HMAC)
    );
    return proxy.proxifyKey<
        HmacCryptoKey,
        proxy.ProxiedCryptoKey<HmacCryptoKey>
    >(handler)(key);
};

/**
 * Import an HMAC key from the specified format
 * @example
 * ```ts
 * const key = await HMAC.importKey("jwk", jwk, {hash: "SHA-512"});
 * ```
 */
export const importKey = async (
    format: KeyFormat,
    key: BufferSource | JsonWebKey,
    algorithm: Omit<params.EnforcedHmacImportParams, "name">,
    extractable: boolean = true,
    keyUsages?: KeyUsage[]
): Promise<proxy.ProxiedCryptoKey<HmacCryptoKey>> => {
    const importedKey = await WebCrypto.importKey<
        HmacCryptoKey,
        params.EnforcedHmacImportParams
    >(
        format as any,
        key as any,
        { ...algorithm, name: Alg.Code.HMAC },
        extractable,
        keyUsages ?? getKeyUsagePairsByAlg(Alg.Code.HMAC)
    );

    return proxy.proxifyKey<
        HmacCryptoKey,
        proxy.ProxiedCryptoKey<HmacCryptoKey>
    >(handler)(importedKey);
};

/**
 * Export an HMAC key into the specified format
 * @example
 * ```ts
 * const jwk = await HMAC.exportKey("jwk", key.self);
 * ```
 * @example
 * ```ts
 * const jwk = await key.exportKey("jwk");
 * ```
 */
export async function exportKey(
    format: KeyFormat,
    key: HmacCryptoKey
): Promise<JsonWebKey | ArrayBuffer> {
    return await WebCrypto.exportKey<HmacCryptoKey>(format as any, key);
}

/**
 * Sign a given payload
 * @example
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await HMAC.sign(key.self, message);
 * ```
 * ```ts
 * const message = new TextEncoder().encode("a message");
 * const signature = await key.sign(message);
 * ```
 */
export async function sign(
    key: HmacCryptoKey,
    data: BufferSource
): Promise<ArrayBuffer> {
    return await WebCrypto.sign<HmacCryptoKey, params.HmacKeyAlgorithm>(
        {
            name: Alg.Code.HMAC,
        },
        key,
        data
    );
}

/**
 * Verify a given signature
 * @example
 * ```ts
 * const isVerified = await HMAC.verify(key, signature, message);
 * ```
 * @example
 * ```ts
 * const isVerified = await key.verify(signature, message);
 * ```
 */
export async function verify(
    key: HmacCryptoKey,
    signature: BufferSource,
    data: BufferSource
): Promise<boolean> {
    return await WebCrypto.verify<HmacCryptoKey, params.HmacKeyAlgorithm>(
        {
            name: Alg.Code.HMAC,
        },
        key,
        signature,
        data
    );
}
