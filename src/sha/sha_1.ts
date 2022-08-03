import * as alg from "../alg";
import { WebCrypto } from "../crypto";
import { ShaShared } from "./shared";

export namespace SHA_1 {
    export const digest = (data: BufferSource) =>
        WebCrypto.digest(alg.SHA.Variant.SHA_1, data);

    export const hexify = ShaShared.hexify;
}
