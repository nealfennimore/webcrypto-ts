import { RSASSA_PKCS1_v1_5 as _RSASSA_PKCS1_v1_5 } from "./rsassa_pkcs1_v1_5.js";
import { RSA_OAEP as _RSA_OAEP } from "./rsa_oaep.js";
import { RSA_PSS as _RSA_PSS } from "./rsa_pss.js";

export type { RsaCryptoKeyPairs, RsaCryptoKeys } from "./shared.js";

export namespace RSA {
    export const RSA_OAEP = _RSA_OAEP;
    export const RSA_PSS = _RSA_PSS;
    export const RSASSA_PKCS1_v1_5 = _RSASSA_PKCS1_v1_5;
}
