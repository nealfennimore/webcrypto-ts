import * as RSA from "../index.js";

const { RSASSA_PKCS1_v1_5 } = RSA;

describe("RSASSA_PKCS1_v1_5", () => {
    describe("Original", () => {
        it("should generate key", async () => {
            const key = await RSASSA_PKCS1_v1_5.generateKey();
            expect(key.self).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSASSA_PKCS1_v1_5.generateKey();

            let jwk = await RSASSA_PKCS1_v1_5.exportKey(
                "jwk",
                keyPair.publicKey.self
            );
            const pubKey = await RSASSA_PKCS1_v1_5.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["verify"]
            );

            expect(jwk).toEqual(
                await RSASSA_PKCS1_v1_5.exportKey("jwk", pubKey.self)
            );

            jwk = await RSASSA_PKCS1_v1_5.exportKey(
                "jwk",
                keyPair.privateKey.self
            );
            const privKey = await RSASSA_PKCS1_v1_5.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["sign"]
            );

            expect(jwk).toEqual(
                await RSASSA_PKCS1_v1_5.exportKey("jwk", privKey.self)
            );
        });
        it("should sign and verify", async () => {
            const keyPair = await RSASSA_PKCS1_v1_5.generateKey();
            const text = encode("a message");
            const signature = await RSASSA_PKCS1_v1_5.sign(
                keyPair.privateKey.self,
                text
            );
            expect(
                await RSASSA_PKCS1_v1_5.verify(
                    keyPair.publicKey.self,
                    signature,
                    text
                )
            ).toEqual(true);
        });
    });
    describe("Proxied", () => {
        it("should generate key", async () => {
            const key = await RSASSA_PKCS1_v1_5.generateKey();
            expect(key).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSASSA_PKCS1_v1_5.generateKey();

            let jwk = await keyPair.publicKey.exportKey("jwk");
            const pubKey = await RSASSA_PKCS1_v1_5.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["verify"]
            );

            expect(jwk).toEqual(await pubKey.exportKey("jwk"));

            jwk = await keyPair.privateKey.exportKey("jwk");
            const privKey = await RSASSA_PKCS1_v1_5.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["sign"]
            );

            expect(jwk).toEqual(await privKey.exportKey("jwk"));
        });
        it("should sign and verify", async () => {
            const keyPair = await RSASSA_PKCS1_v1_5.generateKey();
            const text = encode("a message");
            const signature = await keyPair.privateKey.sign(text);
            expect(await keyPair.publicKey.verify(signature, text)).toEqual(
                true
            );
        });
    });
});
