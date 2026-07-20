import * as Curve25519 from "../index.js";
import {
    Ed25519CryptoKeyPair,
    Ed25519ProxiedCryptoKeyPair,
} from "../shared.js";

const { Ed25519 } = Curve25519;

describe("Ed25519", () => {
    describe("Original", () => {
        let proxiedKeyPair: Ed25519ProxiedCryptoKeyPair;
        let keyPair: Ed25519CryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await Ed25519.generateKey();
            keyPair = proxiedKeyPair.self;
        });

        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await Ed25519.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await Ed25519.importKey("jwk", jwk, true, [
                "verify",
            ]);

            expect(await Ed25519.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await Ed25519.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await Ed25519.importKey("jwk", jwk, true, [
                "sign",
            ]);

            expect(
                await Ed25519.exportKey("jwk", importedPrivKey.self)
            ).toEqual(jwk);
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await Ed25519.sign(keyPair.privateKey, text);

            expect(
                await Ed25519.verify(keyPair.publicKey, signature, text)
            ).toBe(true);
        });
    });

    describe("Proxied", () => {
        let keyPair: Ed25519ProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await Ed25519.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair.self).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await Ed25519.importKey("jwk", jwk, true, [
                "verify",
            ]);

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await Ed25519.importKey("jwk", jwk, true, [
                "sign",
            ]);

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await keyPair.privateKey.sign(text);

            expect(await keyPair.publicKey.verify(signature, text)).toBe(true);
        });
    });
});
