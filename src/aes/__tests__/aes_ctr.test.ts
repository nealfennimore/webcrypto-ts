import * as alg from "../../alg";
import { IV } from "../../iv";
import { AES, AesKey } from "../index";

describe("AES_CTR", () => {
    let iv: Uint8Array, counter: Uint8Array, key: AesKey;
    const text = "brown fox fox fox fox fox fox fox fox fox";
    beforeEach(async () => {
        iv = await IV.generate();
        counter = await AES.AES_CTR.generateCounter();
        key = await AES.AES_CTR.generateKey();
    });
    it("should encrypt and decrypt", async () => {
        const ciphertextBytes = await AES.AES_CTR.encrypt(
            { counter, length: 8 },
            key,
            new TextEncoder().encode(text)
        );
        const plaintextBytes = await AES.AES_CTR.decrypt(
            { counter, length: 8 },
            key,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should import and export keys", async () => {
        const ciphertextBytes = await AES.AES_CTR.encrypt(
            { counter, length: 8 },
            key,
            new TextEncoder().encode(text)
        );

        const jwk = await AES.AES_CTR.exportKey("jwk", key);
        const importedKey = await AES.AES_CTR.importKey("jwk", jwk, {
            length: 256,
        });

        const plaintextBytes = await AES.AES_CTR.decrypt(
            { counter, length: 8 },
            importedKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should wrap and unwrap keys", async () => {
        const kek = await AES.AES_CTR.generateKey({ length: 256 }, true, [
            "wrapKey",
            "unwrapKey",
        ]);
        const dek: AesKey = await AES.AES_CTR.generateKey({ length: 256 });

        const ciphertextBytes = await AES.AES_CTR.encrypt(
            { counter, length: 8 },
            dek,
            new TextEncoder().encode(text)
        );

        const wrappedKey = await AES.AES_CTR.wrapKey("raw", dek, kek, {
            counter,
            length: 8,
        });
        const unwrappedkey = await AES.AES_CTR.unwrapKey(
            "raw",
            wrappedKey,
            { name: alg.AES.Mode.AES_CTR },
            kek,
            { counter, length: 8 }
        );

        const plaintextBytes = await AES.AES_CTR.decrypt(
            { counter, length: 8 },
            unwrappedkey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
});
