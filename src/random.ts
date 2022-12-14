/**
 * Cryptographically strong random values.
 * @module
 */

import * as WebCrypto from "./webcrypto.js";

/**
 * Generate random values
 * @example
 * ```ts
 * const values = await Random.getValues(16);
 * ```
 */
export async function getValues(length: number): Promise<Uint8Array> {
    return await (
        await WebCrypto._crypto
    ).getRandomValues(new Uint8Array(length));
}

/**
 * Initialization Vectors
 */
export namespace IV {
    /**
     * Generate an initialization vector. Defaults to 16 bytes.
     * @example
     * ```ts
     * const iv = await Random.IV.generate();
     * ```
     */
    export async function generate(length: number = 16): Promise<Uint8Array> {
        return await getValues(length);
    }
}

/**
 * Salts
 */
export namespace Salt {
    /**
     * Generate a salt. Defaults to 16 bytes.
     * @example
     * ```ts
     * const salt = await Random.Salt.generate();
     * ```
     */
    export async function generate(length: number = 16): Promise<Uint8Array> {
        return await getValues(length);
    }
}

/**
 * UUID
 */
export namespace UUID {
    /**
     * Generate a UUID.
     * @example
     * ```ts
     * const uuid = await Random.UUID.generate();
     * ```
     */
    export async function generate(): Promise<string> {
        return await (await WebCrypto._crypto).randomUUID();
    }
}
