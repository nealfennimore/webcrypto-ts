import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { Sha256ArrayBuffer, ShaShared } from "./shared.js";

export namespace SHA_256 {
    export const digest = async (data: BufferSource) =>
        WebCrypto.digest<Sha256ArrayBuffer>(alg.SHA.Variant.SHA_256, data);

    export const hexify = (digest: Sha256ArrayBuffer) =>
        ShaShared.hexify(digest);
}
