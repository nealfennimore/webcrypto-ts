import { HKDF as _HKDF } from "./hkdf.js";
import { PBKDF2 as _PBKDF2 } from "./pbkdf.js";

export type { HkdfKeyMaterial, Pbkdf2KeyMaterial } from "./shared.js";

export namespace KDF {
    export const HKDF = _HKDF;
    export const PBKDF2 = _PBKDF2;
}
