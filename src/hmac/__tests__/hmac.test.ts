import * as HMAC from "../index.js";

const skipIf = process.env.NODE_VERSION === "16.x" ? it.skip : it;

describe("HMAC", () => {
    describe("Original", () => {
        let proxiedKey: HMAC.HmacProxiedCryptoKey;
        let key: HMAC.HmacCryptoKey;
        beforeEach(async () => {
            // @ts-ignore
            proxiedKey = await HMAC.generateKey();
            key = proxiedKey.self;
        });
        skipIf("should generate key", async () => {
            expect(key).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await HMAC.exportKey("jwk", key);
            const importedPubKey = await HMAC.importKey("jwk", jwk, {
                hash: "SHA-512",
            });

            expect(await HMAC.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await HMAC.sign(key, text);

            expect(await HMAC.verify(key, signature, text)).toBe(true);
        });
    });
    describe("Proxied", () => {
        let key: HMAC.HmacProxiedCryptoKey;
        beforeEach(async () => {
            key = await HMAC.generateKey();
        });
        skipIf("should generate key", async () => {
            expect(key).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await key.exportKey("jwk");
            const importedPubKey = await HMAC.importKey("jwk", jwk, {
                hash: "SHA-512",
            });

            expect(await HMAC.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await key.sign(text);

            expect(await key.verify(signature, text)).toBe(true);
        });
    });
});
