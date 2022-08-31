import * as Random from "../random.js";

describe("Random", () => {
    it("should generate a random values", async () => {
        let values = await Random.getValues(1);
        expect(values.length).toBe(1);
        expect(values).toBeInstanceOf(Uint8Array);
    });
    it("should generate a random salt", async () => {
        let salt = await Random.Salt.generate();
        expect(salt.length).toBe(16);
        expect(salt).toBeInstanceOf(Uint8Array);

        salt = await Random.Salt.generate(1);
        expect(salt.length).toBe(1);
        expect(salt).toBeInstanceOf(Uint8Array);
    });
    it("should generate a random iv", async () => {
        let iv = await Random.IV.generate();
        expect(iv.length).toBe(16);
        expect(iv).toBeInstanceOf(Uint8Array);

        iv = await Random.IV.generate(1);
        expect(iv.length).toBe(1);
        expect(iv).toBeInstanceOf(Uint8Array);
    });
    it("should generate a random uuid", async () => {
        let uuid = await Random.UUID.generate();
        expect(uuid.length).toBe(36);
        expect(typeof uuid).toBe("string");
    });
});
