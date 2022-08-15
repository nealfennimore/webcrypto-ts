import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { Sha384ArrayBuffer, ShaShared } from "./shared.js";

export namespace SHA_384 {
    export const digest = async (data: BufferSource) =>
        WebCrypto.digest<Sha384ArrayBuffer>(alg.SHA.Variant.SHA_384, data);

    export const hexify = (digest: Sha384ArrayBuffer) =>
        ShaShared.hexify(digest);
}
