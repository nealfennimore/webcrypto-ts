import { SHA } from "../index.js";

describe("SHA_1", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_1.digest(data);
        expect(hash.byteLength).toEqual(20);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_1.digest(data);
        expect(SHA.SHA_1.hexify(hash)).toMatchSnapshot();
    });
});
