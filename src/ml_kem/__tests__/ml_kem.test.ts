import * as AES from "../../aes/index.js";
import * as params from "../../params.js";
import * as ML_KEM from "../index.js";
import { MlKemProxiedCryptoKeyPair } from "../shared.js";

// ML-KEM is only supported on Node.js >= 24.7.0
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
const supported = nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 7);
const describeIf = supported ? describe : describe.skip;

const variants = [
    ["ML-KEM-512", ML_KEM.ML_KEM_512],
    ["ML-KEM-768", ML_KEM.ML_KEM_768],
    ["ML-KEM-1024", ML_KEM.ML_KEM_1024],
] as const;

const aesParams: params.EnforcedAesKeyGenParams = {
    name: AES.Alg.Mode.AES_GCM,
    length: 256,
};

describeIf("ML-KEM", () => {
    variants.forEach(([name, variant]) => {
        describe(name, () => {
            let keyPair: MlKemProxiedCryptoKeyPair;
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
                    ["encapsulateKey", "encapsulateBits"]
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
                    ["decapsulateKey", "decapsulateBits"]
                );

                expect(
                    new Uint8Array(
                        (await importedPrivKey.exportKey(
                            "raw-seed"
                        )) as ArrayBuffer
                    )
                ).toEqual(new Uint8Array(seedBytes));
            });
            it("should encapsulate and decapsulate bits", async () => {
                const { sharedKey, ciphertext } = await variant.encapsulateBits(
                    keyPair.publicKey.self
                );

                expect(new Uint8Array(sharedKey).byteLength).toEqual(32);

                const decapsulated = await variant.decapsulateBits(
                    keyPair.privateKey.self,
                    ciphertext
                );

                expect(new Uint8Array(decapsulated)).toEqual(
                    new Uint8Array(sharedKey)
                );
            });
            it("should encapsulate and decapsulate bits with proxied keys", async () => {
                const { sharedKey, ciphertext } =
                    await keyPair.publicKey.encapsulateBits();

                const decapsulated =
                    await keyPair.privateKey.decapsulateBits(ciphertext);

                expect(new Uint8Array(decapsulated)).toEqual(
                    new Uint8Array(sharedKey)
                );
            });
            it("should encapsulate and decapsulate keys", async () => {
                const { sharedKey, ciphertext } = await variant.encapsulateKey(
                    keyPair.publicKey.self,
                    aesParams
                );

                const decapsulatedKey = await variant.decapsulateKey(
                    keyPair.privateKey.self,
                    ciphertext,
                    aesParams
                );

                const sharedKeyBytes = await crypto.subtle.exportKey(
                    "raw",
                    sharedKey
                );
                const decapsulatedKeyBytes = await crypto.subtle.exportKey(
                    "raw",
                    decapsulatedKey
                );
                expect(new Uint8Array(decapsulatedKeyBytes)).toEqual(
                    new Uint8Array(sharedKeyBytes)
                );
            });
            it("should encapsulate and decapsulate keys with proxied keys", async () => {
                const { sharedKey, ciphertext } =
                    await keyPair.publicKey.encapsulateKey(aesParams);

                const decapsulatedKey =
                    await keyPair.privateKey.decapsulateKey(
                        ciphertext,
                        aesParams
                    );

                const sharedKeyBytes = await crypto.subtle.exportKey(
                    "raw",
                    sharedKey
                );
                const decapsulatedKeyBytes = await crypto.subtle.exportKey(
                    "raw",
                    decapsulatedKey
                );
                expect(new Uint8Array(decapsulatedKeyBytes)).toEqual(
                    new Uint8Array(sharedKeyBytes)
                );
            });
        });
    });
});
