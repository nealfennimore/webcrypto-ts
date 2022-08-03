import { ECDSA } from "../ecdsa";
import { EcKeyPair } from "../shared";

describe("ECDSA", () => {
    let keyPair: EcKeyPair;
    beforeEach(async () => {
        keyPair = await ECDSA.generateKey();
    });
    it("should generate key", async () => {
        expect(keyPair).toMatchSnapshot();
    });
    it("should import and export key", async () => {
        let jwk = await ECDSA.exportKey("jwk", keyPair.publicKey);
        const importedPubKey = await ECDSA.importKey(
            "jwk",
            "P-521",
            jwk,
            true,
            ["verify"]
        );

        expect(await ECDSA.exportKey("jwk", importedPubKey)).toEqual(jwk);

        jwk = await ECDSA.exportKey("jwk", keyPair.privateKey);
        const importedPrivKey = await ECDSA.importKey(
            "jwk",
            "P-521",
            jwk,
            true,
            ["sign"]
        );

        expect(await ECDSA.exportKey("jwk", importedPrivKey)).toEqual(jwk);
    });
    it("should sign and verify", async () => {
        const text = encode("a message");
        const signature = await ECDSA.sign("SHA-512", keyPair.privateKey, text);

        expect(
            await ECDSA.verify("SHA-512", keyPair.publicKey, signature, text)
        ).toBe(true);
    });
});
