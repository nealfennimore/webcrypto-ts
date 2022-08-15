import * as alg from "../../alg.js";
import { IV } from "../../iv.js";
import { AES, AesCbcCryptoKey } from "../index.js";

describe("AES_CBC", () => {
    let iv: Uint8Array, key: AesCbcCryptoKey;
    const text = "brown fox fox fox fox fox fox fox fox fox";
    beforeEach(async () => {
        iv = await IV.generate();
        key = await AES.AES_CBC.generateKey();
    });
    it("should encrypt and decrypt", async () => {
        const ciphertextBytes = await AES.AES_CBC.encrypt(
            { iv },
            key,
            new TextEncoder().encode(text)
        );
        const plaintextBytes = await AES.AES_CBC.decrypt(
            { iv },
            key,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should import and export keys", async () => {
        const ciphertextBytes = await AES.AES_CBC.encrypt(
            { iv },
            key,
            new TextEncoder().encode(text)
        );

        const jwk = await AES.AES_CBC.exportKey("jwk", key);
        const importedKey = await AES.AES_CBC.importKey("jwk", jwk, {
            length: 256,
        });

        const plaintextBytes = await AES.AES_CBC.decrypt(
            { iv },
            importedKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should wrap and unwrap keys", async () => {
        const kek = await AES.AES_CBC.generateKey({ length: 256 }, true, [
            "wrapKey",
            "unwrapKey",
        ]);
        const dek: AesCbcCryptoKey = await AES.AES_CBC.generateKey({
            length: 256,
        });

        const ciphertextBytes = await AES.AES_CBC.encrypt(
            { iv },
            dek,
            new TextEncoder().encode(text)
        );

        const wrappedKey = await AES.AES_CBC.wrapKey("raw", dek, kek, {
            iv,
        });
        const unwrappedkey = (await AES.AES_CBC.unwrapKey(
            "raw",
            wrappedKey,
            { name: alg.AES.Mode.AES_CBC },
            kek,
            { iv }
        )) as AesCbcCryptoKey;

        const plaintextBytes = await AES.AES_CBC.decrypt(
            { iv },
            unwrappedkey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
});
