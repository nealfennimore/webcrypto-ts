import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { ShaShared } from "./shared.js";

export namespace SHA_512 {
    export const digest = (data: BufferSource) =>
        WebCrypto.digest(alg.SHA.Variant.SHA_512, data);

    export const hexify = ShaShared.hexify;
}
