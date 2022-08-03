export namespace ShaShared {
    export const hexify = (digest: ArrayBuffer) =>
        Array.from(new Uint8Array(digest))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
}
