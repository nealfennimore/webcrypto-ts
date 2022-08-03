import { RSASSA_PKCS1_v1_5 as _RSASSA_PKCS1_v1_5 } from "./rsassa_pkcs1_v1_5";
import { RSA_OAEP as _RSA_OAEP } from "./rsa_oaep";
import { RSA_PSS as _RSA_PSS } from "./rsa_pss";

export type { RsaKey, RsaKeyPair } from "./shared";

export namespace RSA {
    export const RSA_OAEP = _RSA_OAEP;
    export const RSA_PSS = _RSA_PSS;
    export const RSASSA_PKCS1_v1_5 = _RSASSA_PKCS1_v1_5;
}
