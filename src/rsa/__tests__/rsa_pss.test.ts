import * as RSA from "../index.js";

const { RSA_PSS } = RSA;

describe("RSA_PSS", () => {
    describe("Original", () => {
        it("should generate key", async () => {
            const key = await RSA_PSS.generateKey();
            expect(key.self).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSA_PSS.generateKey();

            let jwk = await RSA_PSS.exportKey("jwk", keyPair.publicKey.self);
            const pubKey = await RSA_PSS.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["verify"]
            );

            expect(jwk).toEqual(await RSA_PSS.exportKey("jwk", pubKey.self));

            jwk = await RSA_PSS.exportKey("jwk", keyPair.privateKey.self);
            const privKey = await RSA_PSS.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["sign"]
            );

            expect(jwk).toEqual(await RSA_PSS.exportKey("jwk", privKey.self));
        });
        it("should sign and verify", async () => {
            const keyPair = await RSA_PSS.generateKey();
            const text = encode("a message");
            const signature = await RSA_PSS.sign(
                16,
                keyPair.privateKey.self,
                text
            );
            expect(
                await RSA_PSS.verify(
                    16,
                    keyPair.publicKey.self,
                    signature,
                    text
                )
            ).toEqual(true);
        });
    });
    describe("Proxied", () => {
        it("should generate key", async () => {
            const key = await RSA_PSS.generateKey();
            expect(key).toMatchSnapshot();
        });

        it("should import and export key", async () => {
            const keyPair = await RSA_PSS.generateKey();

            let jwk = await keyPair.publicKey.exportKey("jwk");
            const pubKey = await RSA_PSS.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["verify"]
            );

            expect(jwk).toEqual(await pubKey.exportKey("jwk"));

            jwk = await keyPair.privateKey.exportKey("jwk");
            const privKey = await RSA_PSS.importKey(
                "jwk",
                jwk,
                { hash: "SHA-512" },
                true,
                ["sign"]
            );

            expect(jwk).toEqual(await privKey.exportKey("jwk"));
        });
        it("should sign and verify", async () => {
            const keyPair = await RSA_PSS.generateKey();
            const text = encode("a message");
            const signature = await keyPair.privateKey.sign(16, text);
            expect(await keyPair.publicKey.verify(16, signature, text)).toEqual(
                true
            );
        });
    });
});
