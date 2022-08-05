import { RSA } from "../index.js";

const { RSASSA_PKCS1_v1_5 } = RSA;

describe("RSASSA_PKCS1_v1_5", () => {
    it("should generate key", async () => {
        const key = await RSASSA_PKCS1_v1_5.generateKey();
        expect(key).toMatchSnapshot();
    });

    it("should import and export key", async () => {
        const keyPair = await RSASSA_PKCS1_v1_5.generateKey();

        let jwk = await RSASSA_PKCS1_v1_5.exportKey("jwk", keyPair.publicKey);
        const pubKey = await RSASSA_PKCS1_v1_5.importKey(
            "jwk",
            jwk,
            { hash: "SHA-512" },
            true,
            ["verify"]
        );

        expect(jwk).toEqual(await RSASSA_PKCS1_v1_5.exportKey("jwk", pubKey));

        jwk = await RSASSA_PKCS1_v1_5.exportKey("jwk", keyPair.privateKey);
        const privKey = await RSASSA_PKCS1_v1_5.importKey(
            "jwk",
            jwk,
            { hash: "SHA-512" },
            true,
            ["sign"]
        );

        expect(jwk).toEqual(await RSASSA_PKCS1_v1_5.exportKey("jwk", privKey));
    });
    it("should sign and verify", async () => {
        const keyPair = await RSASSA_PKCS1_v1_5.generateKey();
        const text = encode("a message");
        const signature = await RSASSA_PKCS1_v1_5.sign(
            keyPair.privateKey,
            text
        );
        expect(
            await RSASSA_PKCS1_v1_5.verify(keyPair.publicKey, signature, text)
        ).toEqual(true);
    });
});
