import { RSA_PSS } from "../rsa_pss";

describe("RSA_PSS", () => {
    it("should generate key", async () => {
        const key = await RSA_PSS.generateKey();
        expect(key).toMatchSnapshot();
    });

    it("should import and export key", async () => {
        const keyPair = await RSA_PSS.generateKey();

        let jwk = await RSA_PSS.exportKey("jwk", keyPair.publicKey);
        const pubKey = await RSA_PSS.importKey("jwk", "SHA-512", jwk, true, [
            "verify",
        ]);

        expect(jwk).toEqual(await RSA_PSS.exportKey("jwk", pubKey));

        jwk = await RSA_PSS.exportKey("jwk", keyPair.privateKey);
        const privKey = await RSA_PSS.importKey("jwk", "SHA-512", jwk, true, [
            "sign",
        ]);

        expect(jwk).toEqual(await RSA_PSS.exportKey("jwk", privKey));
    });
    it("should sign and verify", async () => {
        const keyPair = await RSA_PSS.generateKey();
        const text = encode("a message");
        const signature = await RSA_PSS.sign(16, keyPair.privateKey, text);
        expect(
            await RSA_PSS.verify(16, keyPair.publicKey, signature, text)
        ).toEqual(true);
    });
});
