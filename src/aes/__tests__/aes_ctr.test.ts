import * as Random from "../../random.js";
import * as AES from "../index.js";

describe("AES_CTR", () => {
    describe("Original", () => {
        let iv: Uint8Array,
            counter: Uint8Array,
            proxiedKey: AES.AesCtrProxiedCryptoKey,
            key: AES.AesCtrCryptoKey;
        const text = "brown fox fox fox fox fox fox fox fox fox";
        beforeEach(async () => {
            iv = await Random.IV.generate();
            counter = await AES.AES_CTR.generateCounter();
            proxiedKey = await AES.AES_CTR.generateKey();
            key = proxiedKey.self;
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
                importedKey.self,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should wrap and unwrap keys", async () => {
            const kek = await AES.AES_CTR.generateKey({ length: 256 }, true, [
                "wrapKey",
                "unwrapKey",
            ]);
            const dek = await AES.AES_CTR.generateKey({
                length: 256,
            });

            const ciphertextBytes = await AES.AES_CTR.encrypt(
                { counter, length: 8 },
                dek.self,
                new TextEncoder().encode(text)
            );

            const wrappedKey = await AES.AES_CTR.wrapKey(
                "raw",
                dek.self,
                kek.self,
                {
                    counter,
                    length: 8,
                }
            );
            const unwrappedKey = (await AES.AES_CTR.unwrapKey(
                "raw",
                wrappedKey,
                { name: AES.Alg.Mode.AES_CTR },
                kek.self,
                { counter, length: 8 }
            )) as AES.AesCtrCryptoKey;

            const plaintextBytes = await AES.AES_CTR.decrypt(
                { counter, length: 8 },
                unwrappedKey,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
    });
    describe("Proxied", () => {
        let iv: Uint8Array,
            counter: Uint8Array,
            key: AES.AesCtrProxiedCryptoKey;
        const text = "brown fox fox fox fox fox fox fox fox fox";
        beforeEach(async () => {
            iv = await Random.IV.generate();
            counter = await AES.AES_CTR.generateCounter();
            key = await AES.AES_CTR.generateKey();
        });
        it("should encrypt and decrypt", async () => {
            const ciphertextBytes = await key.encrypt(
                { counter, length: 8 },
                new TextEncoder().encode(text)
            );
            const plaintextBytes = await key.decrypt(
                { counter, length: 8 },
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should import and export keys", async () => {
            const ciphertextBytes = await key.encrypt(
                { counter, length: 8 },
                new TextEncoder().encode(text)
            );

            const jwk = await key.exportKey("jwk");
            const importedKey = await AES.AES_CTR.importKey("jwk", jwk, {
                length: 256,
            });

            const plaintextBytes = await importedKey.decrypt(
                { counter, length: 8 },
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
        it("should wrap and unwrap keys", async () => {
            const kek = await AES.AES_CTR.generateKey({ length: 256 }, true, [
                "wrapKey",
                "unwrapKey",
            ]);
            const dek = await AES.AES_CTR.generateKey({
                length: 256,
            });

            const ciphertextBytes = await dek.encrypt(
                { counter, length: 8 },
                new TextEncoder().encode(text)
            );

            const wrappedKey = await kek.wrapKey("raw", dek.self, {
                counter,
                length: 8,
            });
            const unwrappedKey = (await kek.unwrapKey(
                "raw",
                wrappedKey,
                { name: AES.Alg.Mode.AES_CTR },
                { counter, length: 8 }
            )) as AES.AesCtrCryptoKey;

            const plaintextBytes = await AES.AES_CTR.decrypt(
                { counter, length: 8 },
                unwrappedKey,
                ciphertextBytes
            );
            expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
        });
    });
});
