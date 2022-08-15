import * as alg from "../../alg.js";
import * as params from "../../params.js";
import { EC } from "../index.js";
import { EcdhCryptoKeyPair } from "../shared.js";

const { ECDH } = EC;

describe("ECDH", () => {
    let keyPair: EcdhCryptoKeyPair;
    beforeEach(async () => {
        keyPair = await ECDH.generateKey();
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

        expect(await ECDH.exportKey("jwk", importedPubKey)).toEqual(jwk);

        jwk = await ECDH.exportKey("jwk", keyPair.privateKey);
        const importedPrivKey = await ECDH.importKey("jwk", jwk, {
            namedCurve: "P-521",
        });

        expect(await ECDH.exportKey("jwk", importedPrivKey)).toEqual(jwk);
    });
    it("should derive bits", async () => {
        const otherKeyPair = await ECDH.generateKey();

        const bits = await ECDH.deriveBits(
            { public: otherKeyPair.publicKey },
            keyPair.privateKey,
            128
        );
        expect(bits.byteLength).toEqual(16);

        await expect(
            ECDH.deriveBits(
                { public: otherKeyPair.publicKey },
                keyPair.privateKey,
                127
            )
        ).rejects.toThrowError(RangeError);
    });
    it("should derive keys", async () => {
        const otherKeyPair = await ECDH.generateKey();
        const hmacParams: params.EnforcedHmacKeyGenParams = {
            name: alg.Authentication.Code.HMAC,
            hash: alg.SHA.Variant.SHA_512,
            length: 512,
        };
        let key = await ECDH.deriveKey(
            { public: otherKeyPair.publicKey },
            keyPair.privateKey,
            hmacParams
        );
        expect(key).toMatchSnapshot();
    });
});
