export namespace IV {
    export async function generate(): Promise<Uint8Array> {
        return await crypto.getRandomValues(new Uint8Array(12));
    }
}
