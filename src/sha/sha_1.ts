import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { Sha1ArrayBuffer, ShaShared } from "./shared.js";

export namespace SHA_1 {
    export const digest = async (data: BufferSource) =>
        WebCrypto.digest<Sha1ArrayBuffer>(alg.SHA.Variant.SHA_1, data);

    export const hexify = (digest: Sha1ArrayBuffer) => ShaShared.hexify(digest);
}
