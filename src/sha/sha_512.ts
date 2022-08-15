import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha512ArrayBuffer, ShaShared } from "./shared.js";

export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha512ArrayBuffer>(Alg.Variant.SHA_512, data);

export const hexify = (digest: Sha512ArrayBuffer) => ShaShared.hexify(digest);
