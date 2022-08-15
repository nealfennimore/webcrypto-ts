import { WebCrypto } from "./crypto.js";

export namespace Random {
    export async function getValues(length: number): Promise<Uint8Array> {
        return await (
            await WebCrypto._crypto
        ).getRandomValues(new Uint8Array(length));
    }

    export namespace IV {
        export async function generate(
            length: number = 16
        ): Promise<Uint8Array> {
            return await Random.getValues(length);
        }
    }
    export namespace Salt {
        export async function generate(
            length: number = 16
        ): Promise<Uint8Array> {
            return await Random.getValues(length);
        }
    }
}
