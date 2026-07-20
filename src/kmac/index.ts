/**
 * All KMAC algorithms. Requires Node.js 24.8.0 or higher.
 * @module
 */
export * as KMAC128 from "./kmac_128.js";
export * as KMAC256 from "./kmac_256.js";
export { Alg } from "./shared.js";
export type { KmacCryptoKey, KmacProxiedCryptoKey } from "./shared.js";
