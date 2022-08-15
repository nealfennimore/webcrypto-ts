import * as alg from "../../alg.js";
import { IV } from "../../iv.js";
import { AES, AesGcmCryptoKey } from "../index.js";

describe("AES_GCM", () => {
    let iv: Uint8Array, key: AesGcmCryptoKey;
    const text = "brown fox fox fox fox fox fox fox fox fox";
    beforeEach(async () => {
        iv = await IV.generate();
        key = await AES.AES_GCM.generateKey({ length: 256 });
    });
    it("should encrypt and decrypt", async () => {
        const ciphertextBytes = await AES.AES_GCM.encrypt(
            { iv },
            key,
            new TextEncoder().encode(text)
        );
        const plaintextBytes = await AES.AES_GCM.decrypt(
            { iv },
            key,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should import and export keys", async () => {
        const ciphertextBytes = await AES.AES_GCM.encrypt(
            { iv },
            key,
            new TextEncoder().encode(text)
        );

        const jwk = await AES.AES_GCM.exportKey("jwk", key);
        const importedKey = await AES.AES_GCM.importKey("jwk", jwk, {
            length: 256,
        });

        const plaintextBytes = await AES.AES_GCM.decrypt(
            { iv },
            importedKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should wrap and unwrap keys", async () => {
        const kek = await AES.AES_GCM.generateKey({ length: 256 }, true, [
            "wrapKey",
            "unwrapKey",
        ]);
        const dek: AesGcmCryptoKey = await AES.AES_GCM.generateKey({
            length: 256,
        });

        const ciphertextBytes = await AES.AES_GCM.encrypt(
            { iv },
            dek,
            new TextEncoder().encode(text)
        );

        const wrappedKey = await AES.AES_GCM.wrapKey("raw", dek, kek, {
            iv,
        });
        const unwrappedkey = (await AES.AES_GCM.unwrapKey(
            "raw",
            wrappedKey,
            { name: alg.AES.Mode.AES_GCM },
            kek,
            { iv }
        )) as AesGcmCryptoKey;

        const plaintextBytes = await AES.AES_GCM.decrypt(
            { iv },
            unwrappedkey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
});
