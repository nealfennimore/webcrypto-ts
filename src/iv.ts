import { Random } from "./random.js";

export namespace IV {
    export async function generate(): Promise<Uint8Array> {
        return await Random.getValues(16);
    }
}
