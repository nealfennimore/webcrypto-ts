import { ECDH as _ECDH } from "./ecdh.js";
import { ECDSA as _ECDSA } from "./ecdsa.js";

export type { EcCryptoKeyPairs, EcCryptoKeys } from "./shared.js";

export namespace EC {
    export const ECDH = _ECDH;
    export const ECDSA = _ECDSA;
}
