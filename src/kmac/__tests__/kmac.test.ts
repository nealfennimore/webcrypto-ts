import * as KMAC from "../index.js";
import { KmacProxiedCryptoKey } from "../shared.js";

// KMAC is only supported on Node.js >= 24.8.0
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
const supported = nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 8);
const describeIf = supported ? describe : describe.skip;

const variants = [
    ["KMAC128", KMAC.KMAC128],
    ["KMAC256", KMAC.KMAC256],
] as const;

describeIf("KMAC", () => {
    variants.forEach(([name, variant]) => {
        describe(name, () => {
            let key: KmacProxiedCryptoKey;
            beforeEach(async () => {
                key = await variant.generateKey();
            });

            it("should generate key", async () => {
                expect(key.self).toMatchSnapshot();
            });
            it("should import and export key", async () => {
                const jwk = await variant.exportKey("jwk", key.self);
                const importedKey = await variant.importKey("jwk", jwk);

                expect(await importedKey.exportKey("jwk")).toEqual(jwk);

                const bytes = (await variant.exportKey(
                    "raw-secret",
                    key.self
                )) as ArrayBuffer;
                const importedRawKey = await variant.importKey(
                    "raw-secret",
                    bytes
                );

                expect(
                    new Uint8Array(
                        (await importedRawKey.exportKey(
                            "raw-secret"
                        )) as ArrayBuffer
                    )
                ).toEqual(new Uint8Array(bytes));
            });
            it("should sign and verify", async () => {
                const text = encode("a message");
                const signature = await variant.sign(
                    { outputLength: 256 },
                    key.self,
                    text
                );

                expect(new Uint8Array(signature).byteLength).toEqual(32);
                expect(
                    await variant.verify(
                        { outputLength: 256 },
                        key.self,
                        signature,
                        text
                    )
                ).toBe(true);
            });
            it("should sign and verify with proxied key", async () => {
                const text = encode("a message");
                const signature = await key.sign({ outputLength: 256 }, text);

                expect(
                    await key.verify({ outputLength: 256 }, signature, text)
                ).toBe(true);
            });
            it("should sign and verify with customization", async () => {
                const text = encode("a message");
                const customization = encode("my-protocol");
                const signature = await key.sign(
                    { outputLength: 256, customization },
                    text
                );

                expect(
                    await key.verify(
                        { outputLength: 256, customization },
                        signature,
                        text
                    )
                ).toBe(true);
                expect(
                    await key.verify(
                        {
                            outputLength: 256,
                            customization: encode("other-protocol"),
                        },
                        signature,
                        text
                    )
                ).toBe(false);
            });
        });
    });
});
