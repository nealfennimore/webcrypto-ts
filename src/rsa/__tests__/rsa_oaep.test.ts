import { AES } from "../../aes/index";
import * as alg from "../../alg";
import { RSA_OAEP } from "../rsa_oaep";

describe("RSA_OAEP", () => {
    it("should generate key", async () => {
        const key = await RSA_OAEP.generateKey();
        expect(key).toMatchSnapshot();
    });

    it("should import and export key", async () => {
        const keyPair = await RSA_OAEP.generateKey();
        const jwk = await RSA_OAEP.exportKey("jwk", keyPair.publicKey);
        const pubKey = await RSA_OAEP.importKey("jwk", "SHA-512", jwk, false, [
            "encrypt",
        ]);
        const text = encode("a message");
        const ciphertext = await RSA_OAEP.encrypt(pubKey, text);
        const plaintext = await RSA_OAEP.decrypt(
            keyPair.privateKey,
            ciphertext
        );
        expect(decode(plaintext)).toEqual(decode(text));
    });
    it("should encrypt and decrypt", async () => {
        const keyPair = await RSA_OAEP.generateKey();
        const text = encode("a message");
        const ciphertext = await RSA_OAEP.encrypt(keyPair.publicKey, text);
        const plaintext = await RSA_OAEP.decrypt(
            keyPair.privateKey,
            ciphertext
        );
        expect(decode(plaintext)).toEqual(decode(text));
    });
    it("should wrap and unwrap key", async () => {
        const aesKey = await AES.AES_CBC.generateKey();
        const keyPair = await RSA_OAEP.generateKey(
            "SHA-512",
            4096,
            new Uint8Array([0x01, 0x00, 0x01]),
            true,
            ["wrapKey", "unwrapKey"]
        );

        const wrappedAesKey = await RSA_OAEP.wrapKey(
            "raw",
            aesKey,
            keyPair.publicKey,
            {}
        );
        const unwrappedAesKey = await RSA_OAEP.unwrapKey(
            "raw",
            wrappedAesKey,
            { name: alg.AES.Mode.AES_CBC },
            keyPair.privateKey,
            {}
        );

        expect(await AES.AES_CBC.exportKey("jwk", aesKey)).toEqual(
            await AES.AES_CBC.exportKey("jwk", unwrappedAesKey)
        );
    });
});
