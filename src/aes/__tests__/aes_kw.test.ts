import * as AES from "../index.js";

describe("AES_KW", () => {
    let key: AES.AesKwCryptoKey;
    beforeEach(async () => {
        key = await AES.AES_KW.generateKey();
    });
    it("should import and export keys", async () => {
        const jwk = await AES.AES_KW.exportKey("jwk", key);
        const importedKek = await AES.AES_KW.importKey("jwk", jwk);
        const exportedKek = await AES.AES_KW.exportKey("jwk", importedKek);

        expect(jwk).toEqual(exportedKek);
    });
    it("should import and export keys", async () => {
        const dek = await AES.AES_CBC.generateKey();

        const wrappedDek = await AES.AES_KW.wrapKey("raw", dek, key);
        const unwrappedDek = (await AES.AES_KW.unwrapKey(
            "raw",
            wrappedDek,
            {
                name: AES.Alg.Mode.AES_CBC,
            },
            key
        )) as AES.AesCbcCryptoKey;

        expect(await AES.AES_CBC.exportKey("jwk", dek)).toEqual(
            await AES.AES_CBC.exportKey("jwk", unwrappedDek)
        );
    });
});
