import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha384ArrayBuffer, ShaShared } from "./shared.js";

export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha384ArrayBuffer>(Alg.Variant.SHA_384, data);

export const hexify = (digest: Sha384ArrayBuffer) => ShaShared.hexify(digest);
