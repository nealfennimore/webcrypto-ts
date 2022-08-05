import { SHA } from "../index.js";

describe("SHA_384", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_384.digest(data);
        expect(hash.byteLength).toEqual(48);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_384.digest(data);
        expect(SHA.SHA_384.hexify(hash)).toMatchSnapshot();
    });
});
