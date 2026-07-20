import * as Authentication from "../../hmac/index.js";
import * as params from "../../params.js";
import * as SHA from "../../sha/index.js";
import * as Curve25519 from "../index.js";
import {
    X25519CryptoKeyPair,
    X25519ProxiedCryptoKeyPair,
} from "../shared.js";

const { X25519 } = Curve25519;

describe("X25519", () => {
    describe("Non-proxied", () => {
        let proxiedKeyPair: X25519ProxiedCryptoKeyPair;
        let keyPair: X25519CryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await X25519.generateKey();
            keyPair = proxiedKeyPair.self;
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await X25519.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await X25519.importKey("jwk", jwk, true, []);

            expect(await X25519.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await X25519.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await X25519.importKey("jwk", jwk);

            expect(await X25519.exportKey("jwk", importedPrivKey.self)).toEqual(
                jwk
            );
        });
        it("should derive bits", async () => {
            const otherKeyPair = await X25519.generateKey();

            const bits = await X25519.deriveBits(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                128
            );
            expect(bits.byteLength).toEqual(16);

            await expect(
                X25519.deriveBits(
                    { public: otherKeyPair.publicKey.self },
                    keyPair.privateKey,
                    127
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            const otherKeyPair = await X25519.generateKey();
            const hmacParams: params.EnforcedHmacKeyGenParams = {
                name: Authentication.Alg.Code.HMAC,
                hash: SHA.Alg.Variant.SHA_512,
                length: 512,
            };
            let key = await X25519.deriveKey(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                hmacParams
            );
            expect(key).toMatchSnapshot();
        });
    });
    describe("Proxied", () => {
        let keyPair: X25519ProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await X25519.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await X25519.importKey("jwk", jwk, true, []);

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await X25519.importKey("jwk", jwk);

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should derive bits", async () => {
            const otherKeyPair = await X25519.generateKey();

            const bits = await keyPair.privateKey.deriveBits(
                { public: otherKeyPair.publicKey.self },
                128
            );
            expect(bits.byteLength).toEqual(16);

            await expect(
                keyPair.privateKey.deriveBits(
                    { public: otherKeyPair.publicKey.self },
                    127
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            const otherKeyPair = await X25519.generateKey();
            const hmacParams: params.EnforcedHmacKeyGenParams = {
                name: Authentication.Alg.Code.HMAC,
                hash: SHA.Alg.Variant.SHA_512,
                length: 512,
            };
            let key = await keyPair.privateKey.deriveKey(
                { public: otherKeyPair.publicKey.self },
                hmacParams
            );
            expect(key).toMatchSnapshot();
        });
    });
});
