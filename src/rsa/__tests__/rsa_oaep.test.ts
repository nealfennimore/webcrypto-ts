import * as AES from "../../aes/index.js";
import * as Random from "../../random.js";
import * as RSA from "../index.js";
import { RsaOaepProxiedPubCryptoKey } from "../shared.js";

const { RSA_OAEP } = RSA;

describe("RSA_OAEP", () => {
    describe("Original", () => {
        let label: BufferSource;
        beforeEach(async () => {
            label = await Random.getValues(8);
        });
        it("should generate key", async () => {
            const key = await RSA_OAEP.generateKey();
            expect(key).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSA_OAEP.generateKey();
            const jwk = await RSA_OAEP.exportKey("jwk", keyPair.publicKey.self);
            const pubKey = (await RSA_OAEP.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                false,
                ["encrypt"]
            )) as RsaOaepProxiedPubCryptoKey;
            const text = encode("a message");
            const ciphertext = await RSA_OAEP.encrypt(
                undefined,
                pubKey.self,
                text
            );
            const plaintext = await RSA_OAEP.decrypt(
                undefined,
                keyPair.privateKey.self,
                ciphertext
            );
            expect(decode(plaintext)).toEqual(decode(text));
        });
        it("should encrypt and decrypt", async () => {
            const keyPair = await RSA_OAEP.generateKey();
            const text = encode("a message");
            const ciphertext = await RSA_OAEP.encrypt(
                { label },
                keyPair.publicKey.self,
                text
            );
            const plaintext = await RSA_OAEP.decrypt(
                { label },
                keyPair.privateKey.self,
                ciphertext
            );
            expect(decode(plaintext)).toEqual(decode(text));
        });
        it("should wrap and unwrap key", async () => {
            const aesKey = await AES.AES_CBC.generateKey();
            const keyPair = await RSA_OAEP.generateKey(
                {
                    hash: "SHA-512",
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                },
                true,
                ["wrapKey", "unwrapKey"]
            );

            const wrappedAesKey = await RSA_OAEP.wrapKey(
                "raw",
                aesKey.self,
                keyPair.publicKey.self,
                {}
            );
            const unwrappedAesKey = (await RSA_OAEP.unwrapKey(
                "raw",
                wrappedAesKey,
                { name: AES.Alg.Mode.AES_CBC },
                keyPair.privateKey.self,
                {}
            )) as AES.AesCbcCryptoKey;

            expect(await AES.AES_CBC.exportKey("jwk", aesKey.self)).toEqual(
                await AES.AES_CBC.exportKey("jwk", unwrappedAesKey)
            );
        });
    });
    describe("Proxied", () => {
        let label: BufferSource;
        beforeEach(async () => {
            label = await Random.getValues(8);
        });
        it("should generate key", async () => {
            const key = await RSA_OAEP.generateKey();
            expect(key).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSA_OAEP.generateKey();
            const jwk = await keyPair.publicKey.exportKey("jwk");
            const pubKey = (await RSA_OAEP.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                false,
                ["encrypt"]
            )) as RsaOaepProxiedPubCryptoKey;
            const text = encode("a message");
            const ciphertext = await pubKey.encrypt({ label }, text);
            const plaintext = await keyPair.privateKey.decrypt(
                { label },
                ciphertext
            );
            expect(decode(plaintext)).toEqual(decode(text));
        });
        it("should encrypt and decrypt", async () => {
            const keyPair = await RSA_OAEP.generateKey();
            const text = encode("a message");
            const ciphertext = await keyPair.publicKey.encrypt({ label }, text);
            const plaintext = await keyPair.privateKey.decrypt(
                { label },
                ciphertext
            );
            expect(decode(plaintext)).toEqual(decode(text));
        });
        it("should wrap and unwrap key", async () => {
            const aesKey = await AES.AES_CBC.generateKey();
            const keyPair = await RSA_OAEP.generateKey(
                {
                    hash: "SHA-512",
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                },
                true,
                ["wrapKey", "unwrapKey"]
            );

            const wrappedAesKey = await keyPair.publicKey.wrapKey(
                "raw",
                aesKey.self,
                {}
            );
            const unwrappedAesKey = (await keyPair.privateKey.unwrapKey(
                "raw",
                wrappedAesKey,
                { name: AES.Alg.Mode.AES_CBC },
                {}
            )) as AES.AesCbcCryptoKey;

            expect(await AES.AES_CBC.exportKey("jwk", aesKey.self)).toEqual(
                await AES.AES_CBC.exportKey("jwk", unwrappedAesKey)
            );
        });
    });
});
