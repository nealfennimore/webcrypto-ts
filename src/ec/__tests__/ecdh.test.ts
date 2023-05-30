import * as Authentication from "../../hmac/index.js";
import * as params from "../../params.js";
import * as SHA from "../../sha/index.js";
import * as EC from "../index.js";
import { EcdhCryptoKeyPair, EcdhProxiedCryptoKeyPair } from "../shared.js";

const { ECDH } = EC;

describe("ECDH", () => {
    describe("Non-proxied", () => {
        let proxiedKeyPair: EcdhProxiedCryptoKeyPair;
        let keyPair: EcdhCryptoKeyPair;
        beforeEach(async () => {
            proxiedKeyPair = await ECDH.generateKey();
            keyPair = proxiedKeyPair.self;
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await ECDH.exportKey("jwk", keyPair.publicKey);
            const importedPubKey = await ECDH.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                []
            );

            expect(await ECDH.exportKey("jwk", importedPubKey.self)).toEqual(
                jwk
            );

            jwk = await ECDH.exportKey("jwk", keyPair.privateKey);
            const importedPrivKey = await ECDH.importKey("jwk", jwk, {
                namedCurve: "P-521",
            });

            expect(await ECDH.exportKey("jwk", importedPrivKey.self)).toEqual(
                jwk
            );
        });
        it("should derive bits", async () => {
            const otherKeyPair = await ECDH.generateKey();

            const bits = await ECDH.deriveBits(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                128
            );
            expect(bits.byteLength).toEqual(16);

            await expect(
                ECDH.deriveBits(
                    { public: otherKeyPair.publicKey.self },
                    keyPair.privateKey,
                    127
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            const otherKeyPair = await ECDH.generateKey();
            const hmacParams: params.EnforcedHmacKeyGenParams = {
                name: Authentication.Alg.Code.HMAC,
                hash: SHA.Alg.Variant.SHA_512,
                length: 512,
            };
            let key = await ECDH.deriveKey(
                { public: otherKeyPair.publicKey.self },
                keyPair.privateKey,
                hmacParams
            );
            expect(key).toMatchSnapshot();
        });
    });
    describe("Proxied", () => {
        let keyPair: EcdhProxiedCryptoKeyPair;
        beforeEach(async () => {
            keyPair = await ECDH.generateKey();
        });
        it("should generate key", async () => {
            expect(keyPair).toMatchSnapshot();
        });
        it("should import and export key", async () => {
            let jwk = await keyPair.publicKey.exportKey("jwk");
            const importedPubKey = await ECDH.importKey(
                "jwk",
                jwk,
                { namedCurve: "P-521" },
                true,
                []
            );

            expect(await importedPubKey.exportKey("jwk")).toEqual(jwk);

            jwk = await keyPair.privateKey.exportKey("jwk");
            const importedPrivKey = await ECDH.importKey("jwk", jwk, {
                namedCurve: "P-521",
            });

            expect(await importedPrivKey.exportKey("jwk")).toEqual(jwk);
        });
        it("should derive bits", async () => {
            const otherKeyPair = await ECDH.generateKey();

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
            const otherKeyPair = await ECDH.generateKey();
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
