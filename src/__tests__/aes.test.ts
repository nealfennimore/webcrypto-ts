import { PBKDF2 } from "../kdf";
import { AES, AesKey } from "../aes";
import { Salt } from "../salt";
import { IV } from "../iv";
import * as alg from "../alg";
import * as params from "../params";

describe("AES", () => {
    let iv: Uint8Array,
        dataEncryptionKey: AesKey,
        aesParams: params.EnforcedAesKeyGenParams;
    const text = "brown fox fox fox fox fox fox fox fox fox";
    beforeEach(async () => {
        iv = await IV.generate();
        aesParams = { name: alg.AES.Mode.AES_GCM, length: 256 };
        dataEncryptionKey = await AES.generateKey(aesParams);
    });
    it("should encrypt and decrypt", async () => {
        const ciphertextBytes = await AES.encrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            dataEncryptionKey,
            new TextEncoder().encode(text)
        );
        const plaintextBytes = await AES.decrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            dataEncryptionKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should import and export keys", async () => {
        const ciphertextBytes = await AES.encrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            dataEncryptionKey,
            new TextEncoder().encode(text)
        );

        const jwk = await AES.exportKey("jwk", dataEncryptionKey);
        const importedKey = await AES.importKey(
            "jwk",
            { name: alg.AES.Mode.AES_GCM, length: 256 },
            jwk
        );

        const plaintextBytes = await AES.decrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            importedKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
    it("should wrap and unwrap keys", async () => {
        const wrappingKeyMaterial = await PBKDF2.generateKeyMaterial(
            "raw",
            new TextEncoder().encode("password")
        );
        const wrappingSalt = await Salt.generate();
        const keyEncryptionKey = await PBKDF2.deriveKey(
            wrappingKeyMaterial,
            wrappingSalt,
            "SHA-512",
            { name: alg.AES.Mode.AES_KW, length: 256 }
        );

        const ciphertextBytes = await AES.encrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            dataEncryptionKey,
            new TextEncoder().encode(text)
        );

        const wrappedKey = await AES.wrapKey(
            "jwk",
            dataEncryptionKey,
            keyEncryptionKey,
            { name: alg.AES.Mode.AES_KW }
        );
        const unwrappedDataEncryptionKey = await AES.unwrapKey(
            "jwk",
            wrappedKey,
            { name: alg.AES.Mode.AES_GCM },
            keyEncryptionKey,
            { name: alg.AES.Mode.AES_KW }
        );

        const plaintextBytes = await AES.decrypt(
            { name: alg.AES.Mode.AES_GCM, iv },
            unwrappedDataEncryptionKey,
            ciphertextBytes
        );
        expect(new TextDecoder().decode(plaintextBytes)).toEqual(text);
    });
});
