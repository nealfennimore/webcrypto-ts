import { HMAC, HmacKey } from "../index";

describe("HMAC", () => {
    let key: HmacKey;
    beforeEach(async () => {
        key = await HMAC.generateKey();
    });
    it("should generate key", async () => {
        expect(key).toMatchSnapshot();
    });
    it("should import and export key", async () => {
        let jwk = await HMAC.exportKey("jwk", key);
        const importedPubKey = await HMAC.importKey("jwk", jwk, {
            hash: "SHA-512",
        });

        expect(await HMAC.exportKey("jwk", importedPubKey)).toEqual(jwk);
    });
    it("should sign and verify", async () => {
        const text = encode("a message");
        const signature = await HMAC.sign(key, text);

        expect(await HMAC.verify(key, signature, text)).toBe(true);
    });
});
