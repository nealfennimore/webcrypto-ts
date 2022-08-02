export namespace Salt {
    export async function generate(): Promise<Uint8Array> {
        return await crypto.getRandomValues(new Uint8Array(16));
    }
}
