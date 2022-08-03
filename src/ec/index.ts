import { ECDH as _ECDH } from "./ecdh";
import { ECDSA as _ECDSA } from "./ecdsa";

export type { EcKey, EcKeyPair } from "./shared";

export namespace EC {
    export const ECDH = _ECDH;
    export const ECDSA = _ECDSA;
}
