export interface Sha1ArrayBuffer extends ArrayBuffer {
    _sha1ArrayBufferBrand: any;
}
export interface Sha256ArrayBuffer extends ArrayBuffer {
    _sha256ArrayBufferBrand: any;
}
export interface Sha384ArrayBuffer extends ArrayBuffer {
    _sha384ArrayBufferBrand: any;
}
export interface Sha512ArrayBuffer extends ArrayBuffer {
    _sha512ArrayBufferBrand: any;
}

export type ShaArrayBuffers =
    | Sha1ArrayBuffer
    | Sha256ArrayBuffer
    | Sha384ArrayBuffer
    | Sha512ArrayBuffer;

export namespace ShaShared {
    export const hexify = (digest: ShaArrayBuffers) =>
        Array.from(new Uint8Array(digest))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
}
