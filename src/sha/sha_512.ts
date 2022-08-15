import * as alg from "../alg.js";
import { WebCrypto } from "../crypto.js";
import { Sha512ArrayBuffer, ShaShared } from "./shared.js";

export namespace SHA_512 {
    export const digest = async (data: BufferSource) =>
        WebCrypto.digest<Sha512ArrayBuffer>(alg.SHA.Variant.SHA_512, data);

    export const hexify = (digest: Sha512ArrayBuffer) =>
        ShaShared.hexify(digest);
}
