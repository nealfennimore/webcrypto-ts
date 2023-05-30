import * as AES from "../index.js";

describe("AES_KW", () => {
    describe("Original", () => {
        let proxiedKey: AES.AesKwProxiedCryptoKey;
        let key: AES.AesKwCryptoKey;
        beforeEach(async () => {
            proxiedKey = await AES.AES_KW.generateKey();
            key = proxiedKey.self;
        });
        it("should import and export keys", async () => {
            const jwk = await AES.AES_KW.exportKey("jwk", key);
            const importedKek = await AES.AES_KW.importKey("jwk", jwk);
            const exportedKek = await AES.AES_KW.exportKey(
                "jwk",
                importedKek.self
            );

            expect(jwk).toEqual(exportedKek);
        });
        it("should wrap and unwrap keys", async () => {
            const dek = await AES.AES_CBC.generateKey();

            const wrappedDek = await AES.AES_KW.wrapKey("raw", dek.self, key);
            const unwrappedDek = (await AES.AES_KW.unwrapKey(
                "raw",
                wrappedDek,
                {
                    name: AES.Alg.Mode.AES_CBC,
                },
                key
            )) as AES.AesCbcCryptoKey;

            expect(await AES.AES_CBC.exportKey("jwk", dek.self)).toEqual(
                await AES.AES_CBC.exportKey("jwk", unwrappedDek)
            );
        });
    });
    describe("Proxied", () => {
        let key: AES.AesKwProxiedCryptoKey;
        beforeEach(async () => {
            key = await AES.AES_KW.generateKey();
        });
        it("should import and export keys", async () => {
            const jwk = await key.exportKey("jwk");
            const importedKek = await AES.AES_KW.importKey("jwk", jwk);
            const exportedKek = await importedKek.exportKey("jwk");

            expect(jwk).toEqual(exportedKek);
        });
        it("should wrap and unwrap keys", async () => {
            const dek = await AES.AES_CBC.generateKey();

            const wrappedDek = await key.wrapKey("raw", dek.self);
            const unwrappedDek = (await key.unwrapKey("raw", wrappedDek, {
                name: AES.Alg.Mode.AES_CBC,
            })) as AES.AesCbcCryptoKey;

            expect(await AES.AES_CBC.exportKey("jwk", dek.self)).toEqual(
                await AES.AES_CBC.exportKey("jwk", unwrappedDek)
            );
        });
    });
});
