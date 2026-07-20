import * as ML_DSA from "../index.js";
import { MlDsaProxiedCryptoKeyPair } from "../shared.js";

// ML-DSA is only supported on Node.js >= 24.7.0
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
const supported = nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 7);
const describeIf = supported ? describe : describe.skip;

const variants = [
    ["ML-DSA-44", ML_DSA.ML_DSA_44],
    ["ML-DSA-65", ML_DSA.ML_DSA_65],
    ["ML-DSA-87", ML_DSA.ML_DSA_87],
] as const;

describeIf("ML-DSA", () => {
    variants.forEach(([name, variant]) => {
        describe(name, () => {
            let keyPair: MlDsaProxiedCryptoKeyPair;
            beforeEach(async () => {
                keyPair = await variant.generateKey();
            });

            it("should generate key", async () => {
                expect(keyPair.self).toMatchSnapshot();
            });
            it("should import and export key", async () => {
                const pubKeyBytes = (await variant.exportKey(
                    "raw-public",
                    keyPair.publicKey.self
                )) as ArrayBuffer;
                const importedPubKey = await variant.importKey(
                    "raw-public",
                    pubKeyBytes,
                    true,
                    ["verify"]
                );

                expect(
                    new Uint8Array(
                        (await importedPubKey.exportKey(
                            "raw-public"
                        )) as ArrayBuffer
                    )
                ).toEqual(new Uint8Array(pubKeyBytes));

                const seedBytes = (await variant.exportKey(
                    "raw-seed",
                    keyPair.privateKey.self
                )) as ArrayBuffer;
                const importedPrivKey = await variant.importKey(
                    "raw-seed",
                    seedBytes,
                    true,
                    ["sign"]
                );

                expect(
                    new Uint8Array(
                        (await importedPrivKey.exportKey(
                            "raw-seed"
                        )) as ArrayBuffer
                    )
                ).toEqual(new Uint8Array(seedBytes));
            });
            it("should sign and verify", async () => {
                const text = encode("a message");
                const signature = await variant.sign(
                    keyPair.privateKey.self,
                    text
                );

                expect(
                    await variant.verify(
                        keyPair.publicKey.self,
                        signature,
                        text
                    )
                ).toBe(true);
            });
            it("should sign and verify with proxied keys", async () => {
                const text = encode("a message");
                const signature = await keyPair.privateKey.sign(text);

                expect(await keyPair.publicKey.verify(signature, text)).toBe(
                    true
                );
            });
            it("should sign and verify with context", async () => {
                const text = encode("a message");
                const context = encode("a context");
                const signature = await keyPair.privateKey.sign(text, {
                    context,
                });

                expect(
                    await keyPair.publicKey.verify(signature, text, {
                        context,
                    })
                ).toBe(true);
                expect(
                    await keyPair.publicKey.verify(signature, text, {
                        context: encode("another context"),
                    })
                ).toBe(false);
            });
        });
    });
});
