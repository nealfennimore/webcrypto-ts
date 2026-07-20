import * as Curve448 from "../index.js";
import { Ed448CryptoKeyPair, Ed448ProxiedCryptoKeyPair } from "../shared.js";

const { Ed448 } = Curve448;

// Non-empty Ed448 context is only supported on Node.js >= 24.8.0
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
const supportsContext = nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 8);
const itContext = supportsContext ? it : it.skip;

describe("Ed448", () => {
    describe("Original", () => {
        let proxiedKeyPair: Ed448ProxiedCryptoKeyPair;
        let keyPair: Ed448CryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await Ed448.generateKey();
            keyPair = proxiedKeyPair.self;
        });

        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await Ed448.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await Ed448.importKey("jwk", jwk, true, [
                "verify",
            ]);

            expect(await Ed448.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await Ed448.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await Ed448.importKey("jwk", jwk, true, [
                "sign",
            ]);

            expect(await Ed448.exportKey("jwk", importedPrivKey.self)).toEqual(
                jwk
            );
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await Ed448.sign(keyPair.privateKey, text);

            expect(await Ed448.verify(keyPair.publicKey, signature, text)).toBe(
                true
            );
        });
        itContext("should sign and verify with context", async () => {
            const text = encode("a message");
            const context = encode("a context");
            const signature = await Ed448.sign(keyPair.privateKey, text, {
                context,
            });

            expect(
                await Ed448.verify(keyPair.publicKey, signature, text, {
                    context,
                })
            ).toBe(true);
            expect(
                await Ed448.verify(keyPair.publicKey, signature, text, {
                    context: encode("another context"),
                })
            ).toBe(false);
        });
    });

    describe("Proxied", () => {
        let keyPair: Ed448ProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await Ed448.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair.self).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await Ed448.importKey("jwk", jwk, true, [
                "verify",
            ]);

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await Ed448.importKey("jwk", jwk, true, [
                "sign",
            ]);

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should sign and verify", async () => {
            const text = encode("a message");
            const signature = await keyPair.privateKey.sign(text);

            expect(await keyPair.publicKey.verify(signature, text)).toBe(true);
        });
        itContext("should sign and verify with context", async () => {
            const text = encode("a message");
            const context = encode("a context");
            const signature = await keyPair.privateKey.sign(text, { context });

            expect(
                await keyPair.publicKey.verify(signature, text, { context })
            ).toBe(true);
        });
    });
});
