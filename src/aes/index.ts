import { AES_CBC as _AES_CBC } from "./aes_cbc";
import { AES_CTR as _AES_CTR } from "./aes_ctr";
import { AES_GCM as _AES_GCM } from "./aes_gcm";
import { AES_KW as _AES_KW } from "./aes_kw";

export type { AesKey } from "./shared";

export namespace AES {
    export const AES_CBC = _AES_CBC;
    export const AES_CTR = _AES_CTR;
    export const AES_GCM = _AES_GCM;
    export const AES_KW = _AES_KW;
}
