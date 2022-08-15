/**
 * Code related to SHA_512
 * @module
 */

import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha512ArrayBuffer, ShaShared } from "./shared.js";

/**
 * Get the digest of the buffer
 * @example
 * ```ts
 * const buffer = new TextEncoder().encode("a file");
 * const digest = SHA_512.digest(buffer);
 * ```
 */
export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha512ArrayBuffer>(Alg.Variant.SHA_512, data);

/**
 * Get the hex string of the digest
 * @example
 * ```ts
 * const hash = SHA_512.hexify(digest);
 * ```
 */
export const hexify = (digest: Sha512ArrayBuffer) => ShaShared.hexify(digest);
