import { WebCrypto } from "./crypto.js";

export namespace Random {
    export async function getValues(length: number): Promise<Uint8Array> {
        return await (
            await WebCrypto._crypto
        ).getRandomValues(new Uint8Array(length));
    }
}
