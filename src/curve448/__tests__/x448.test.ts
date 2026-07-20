import * as AES from "../../aes/index.js";
import * as params from "../../params.js";
import * as Curve448 from "../index.js";
import { X448CryptoKeyPair, X448ProxiedCryptoKeyPair } from "../shared.js";

const { X448 } = Curve448;

describe("X448", () => {
    describe("Non-proxied", () => {
        let proxiedKeyPair: X448ProxiedCryptoKeyPair;
        let keyPair: X448CryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await X448.generateKey();
            keyPair = proxiedKeyPair.self;
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await X448.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await X448.importKey("jwk", jwk, true, []);

            expect(await X448.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await X448.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await X448.importKey("jwk", jwk);

            expect(await X448.exportKey("jwk", importedPrivKey.self)).toEqual(
                jwk
            );
        });
        it("should derive bits", async () => {
            const otherKeyPair = await X448.generateKey();

            const bits = await X448.deriveBits(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                128
            );
            expect(bits.byteLength).toEqual(16);

            await expect(
                X448.deriveBits(
                    { public: otherKeyPair.publicKey.self },
                    keyPair.privateKey,
                    127
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            const otherKeyPair = await X448.generateKey();
            const aesParams: params.EnforcedAesKeyGenParams = {
                name: AES.Alg.Mode.AES_GCM,
                length: 256,
            };
            let key = await X448.deriveKey(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                aesParams
            );
            expect(key).toMatchSnapshot();
        });
    });
    describe("Proxied", () => {
        let keyPair: X448ProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await X448.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await X448.importKey("jwk", jwk, true, []);

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await X448.importKey("jwk", jwk);

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should derive bits", async () => {
            const otherKeyPair = await X448.generateKey();

            const bits = await keyPair.privateKey.deriveBits(
                { public: otherKeyPair.publicKey.self },
                128
            );
            expect(bits.byteLength).toEqual(16);
        });
        it("should derive keys", async () => {
            const otherKeyPair = await X448.generateKey();
            const aesParams: params.EnforcedAesKeyGenParams = {
                name: AES.Alg.Mode.AES_GCM,
                length: 256,
            };
            let key = await keyPair.privateKey.deriveKey(
                { public: otherKeyPair.publicKey.self },
                aesParams
            );
            expect(key).toMatchSnapshot();
        });
    });
});
