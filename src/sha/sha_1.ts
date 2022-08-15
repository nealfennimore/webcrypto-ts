import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha1ArrayBuffer, ShaShared } from "./shared.js";

export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha1ArrayBuffer>(Alg.Variant.SHA_1, data);

export const hexify = (digest: Sha1ArrayBuffer) => ShaShared.hexify(digest);
