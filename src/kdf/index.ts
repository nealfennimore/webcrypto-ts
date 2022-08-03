import { HKDF as _HKDF } from "./hkdf";
import { PBKDF2 as _PBKDF2 } from "./pbkdf";

export type { HkdfKeyMaterial, Pbkdf2KeyMaterial } from "./shared";

export namespace KDF {
    export const HDKF = _HKDF;
    export const PBKDF2 = _PBKDF2;
}
