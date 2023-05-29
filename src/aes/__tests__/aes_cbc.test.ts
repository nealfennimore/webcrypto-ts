import * as Random from "../../random.js";
import { AesCbcProxiedCryptoKey } from "../aes_cbc.js";
import * as AES from "../index.js";

describe("AES_CBC", () => {
    describe("Original", () => {
        let iv: Uint8Array,
            proxiedKey: AesCbcProxiedCryptoKey,
            key: AES.AesCbcCryptoKey;
        const text = "brown fox fox fox fox fox fox fox fox fox";
        beforeEach(async () => {
            iv = await Random.IV.generate();
            proxiedKey = await AES.AES_CBC.generateKey();
            key = proxiedKey.self;
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
                importedKey.self,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should wrap and unwrap keys", async () => {
            const kek = await AES.AES_CBC.generateKey({ length: 256 }, true, [
                "wrapKey",
                "unwrapKey",
            ]);
            const dek = await AES.AES_CBC.generateKey({
                length: 256,
            });

            const ciphertextBytes = await AES.AES_CBC.encrypt(
                { iv },
                dek.self,
                new TextEncoder().encode(text)
            );

            const wrappedKey = await AES.AES_CBC.wrapKey(
                "raw",
                dek.self,
                kek.self,
                {
                    iv,
                }
            );
            const unwrappedkey = (await AES.AES_CBC.unwrapKey(
                "raw",
                wrappedKey,
                { name: AES.Alg.Mode.AES_CBC },
                kek.self,
                { iv }
            )) as AES.AesCbcCryptoKey;

            const plaintextBytes = await AES.AES_CBC.decrypt(
                { iv },
                unwrappedkey,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
    });
    describe("Proxied", () => {
        let iv: Uint8Array, key: AesCbcProxiedCryptoKey;
        const text = "brown fox fox fox fox fox fox fox fox fox";
        beforeEach(async () => {
            iv = await Random.IV.generate();
            key = await AES.AES_CBC.generateKey();
        });
        it("should encrypt and decrypt", async () => {
            const ciphertextBytes = await key.encrypt(
                { iv },
                new TextEncoder().encode(text)
            );
            const plaintextBytes = await key.decrypt({ iv }, ciphertextBytes);
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should import and export keys", async () => {
            const ciphertextBytes = await key.encrypt(
                { iv },
                new TextEncoder().encode(text)
            );

            const jwk = await key.exportKey("jwk");
            const importedKey = await AES.AES_CBC.importKey("jwk", jwk, {
                length: 256,
            });

            const plaintextBytes = await importedKey.decrypt(
                { iv },
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should wrap and unwrap keys", async () => {
            const kek = await AES.AES_CBC.generateKey({ length: 256 }, true, [
                "wrapKey",
                "unwrapKey",
            ]);
            const dek = await AES.AES_CBC.generateKey({
                length: 256,
            });

            const ciphertextBytes = await dek.encrypt(
                { iv },
                new TextEncoder().encode(text)
            );

            const wrappedKey = await kek.wrapKey("raw", dek.self, {
                iv,
            });
            const unwrappedkey = (await kek.unwrapKey(
                "raw",
                wrappedKey,
                { name: AES.Alg.Mode.AES_CBC },
                { iv }
            )) as AES.AesCbcCryptoKey;

            const plaintextBytes = await AES.AES_CBC.decrypt(
                { iv },
                unwrappedkey,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
    });
});
