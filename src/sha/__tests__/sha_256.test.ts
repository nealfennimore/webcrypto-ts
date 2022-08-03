import { SHA_256 } from "../sha_256";

describe("SHA_256", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA_256.digest(data);
        expect(hash.byteLength).toEqual(32);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA_256.digest(data);
        expect(SHA_256.hexify(hash)).toMatchSnapshot();
    });
});
