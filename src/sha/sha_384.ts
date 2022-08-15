/**
 * Code related to SHA_384
 * @module
 */

import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha384ArrayBuffer, ShaShared } from "./shared.js";

/**
 * Get the digest of the buffer
 * @example
 * ```ts
 * const buffer = new TextEncoder().encode("a file");
 * const digest = SHA_384.digest(buffer);
 * ```
 */
export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha384ArrayBuffer>(Alg.Variant.SHA_384, data);

/**
 * Get the hex string of the digest
 * @example
 * ```ts
 * const hash = SHA_384.hexify(digest);
 * ```
 */
export const hexify = (digest: Sha384ArrayBuffer) => ShaShared.hexify(digest);
