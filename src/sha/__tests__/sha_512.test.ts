import { SHA_512 } from "../sha_512";

describe("SHA_512", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA_512.digest(data);
        expect(hash.byteLength).toEqual(64);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA_512.digest(data);
        expect(SHA_512.hexify(hash)).toMatchSnapshot();
    });
});
