/**
 * Code related to SHA_256
 * @module
 */

import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha256ArrayBuffer, ShaShared } from "./shared.js";

/**
 * Get the digest of the buffer
 * @example
 * ```ts
 * const buffer = new TextEncoder().encode("a file");
 * const digest = SHA_256.digest(buffer);
 * ```
 */
export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha256ArrayBuffer>(Alg.Variant.SHA_256, data);

/**
 * Get the hex string of the digest
 * @example
 * ```ts
 * const hash = SHA_256.hexify(digest);
 * ```
 */
export const hexify = (digest: Sha256ArrayBuffer) => ShaShared.hexify(digest);
