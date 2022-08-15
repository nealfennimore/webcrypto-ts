import * as WebCrypto from "../webcrypto.js";
import { Alg, Sha256ArrayBuffer, ShaShared } from "./shared.js";

export const digest = async (data: BufferSource) =>
    WebCrypto.digest<Sha256ArrayBuffer>(Alg.Variant.SHA_256, data);

export const hexify = (digest: Sha256ArrayBuffer) => ShaShared.hexify(digest);
