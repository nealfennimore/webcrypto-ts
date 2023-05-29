import * as EC from "../index.js";
import { EcdsaCryptoKeyPair, EcdsaProxiedCryptoKeyPair } from "../shared.js";

const { ECDSA } = EC;

describe("ECDSA", () => {
    describe("Original", () => {
        let proxiedKeyPair: EcdsaProxiedCryptoKeyPair;
        let keyPair: EcdsaCryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await ECDSA.generateKey();
            keyPair = proxiedKeyPair.self;
        });

        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await ECDSA.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await ECDSA.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                ["verify"]
            );

            expect(await ECDSA.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await ECDSA.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await ECDSA.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                ["sign"]
            );

            expect(await ECDSA.exportKey("jwk", importedPrivKey.self)).toEqual(
                jwk
            );
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await ECDSA.sign(
                { hash: "SHA-512" },
                keyPair.privateKey,
                text
            );

            expect(
                await ECDSA.verify(
                    { hash: "SHA-512" },
                    keyPair.publicKey,
                    signature,
                    text
                )
            ).toBe(true);
        });
    });

    describe("Proxied", () => {
        let keyPair: EcdsaProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await ECDSA.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair.self).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await ECDSA.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                ["verify"]
            );

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await ECDSA.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                ["sign"]
            );

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await keyPair.privateKey.sign(
                { hash: "SHA-512" },
                text
            );

            expect(
                await keyPair.publicKey.verify(
                    { hash: "SHA-512" },
                    signature,
                    text
                )
            ).toBe(true);
        });
    });
});
