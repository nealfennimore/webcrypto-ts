import { SHA } from "../index";

describe("SHA_256", () => {
    it("should hash", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_256.digest(data);
        expect(hash.byteLength).toEqual(32);
    });
    it("should hexify", async () => {
        const data = encode("a message");
        const hash = await SHA.SHA_256.digest(data);
        expect(SHA.SHA_256.hexify(hash)).toMatchSnapshot();
    });
});
