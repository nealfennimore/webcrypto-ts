import { SHA_384 } from "../sha_384";

describe("SHA_384", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA_384.digest(data);
        expect(hash.byteLength).toEqual(48);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA_384.digest(data);
        expect(SHA_384.hexify(hash)).toMatchSnapshot();
    });
});
