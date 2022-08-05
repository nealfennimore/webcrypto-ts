import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { ShaShared } from "./shared.js";

export namespace SHA_1 {
    export const digest = (data: BufferSource) =>
        WebCrypto.digest(alg.SHA.Variant.SHA_1, data);

    export const hexify = ShaShared.hexify;
}
