/**
 * Code related to SHA_1
 * @module
 */

import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha1ArrayBuffer, ShaShared } from "./shared.js";

/**
 * Get the digest of the buffer
 * @example
 * ```ts
 * const buffer = new TextEncoder().encode("a file");
 * const digest = SHA_1.digest(buffer);
 * ```
 */
export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha1ArrayBuffer>(Alg.Variant.SHA_1, data);

/**
 * Get the hex string of the digest
 * @example
 * ```ts
 * const hash = SHA_1.hexify(digest);
 * ```
 */
export const hexify = (digest: Sha1ArrayBuffer) => ShaShared.hexify(digest);
