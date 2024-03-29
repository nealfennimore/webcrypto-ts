import { Alg as AES } from "../../aes/shared.js";
import { Alg as Authentication } from "../../hmac/index.js";
import * as params from "../../params.js";
import * as Random from "../../random.js";
import { Alg as SHA } from "../../sha/shared.js";
import * as KDF from "../index.js";
import type { HkdfKeyMaterial, HkdfProxiedKeyMaterial } from "../shared.js";

const { HKDF } = KDF;
describe("HKDF", () => {
    describe("Original", () => {
        let proxiedKeyMaterial: HkdfProxiedKeyMaterial,
            keyMaterial: HkdfKeyMaterial,
            salt: Uint8Array,
            info: Uint8Array;
        beforeEach(async () => {
            proxiedKeyMaterial = await HKDF.generateKeyMaterial(
                "raw",
                new TextEncoder().encode("password")
            );
            keyMaterial = proxiedKeyMaterial.self;

            salt = await Random.Salt.generate();
            info = await Random.Salt.generate();
        });
        it("should derive bits", async () => {
            const bits = await HKDF.deriveBits(
                { salt, info, hash: SHA.Variant.SHA_512 },
                keyMaterial,
                512
            );
            expect(bits.byteLength).toEqual(64);

            await expect(
                HKDF.deriveBits(
                    { salt, info, hash: SHA.Variant.SHA_512 },
                    keyMaterial,
                    511
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            for (const [aesKey, aesVal] of Object.entries(AES.Mode)) {
                for (const [shaKey, shaVal] of Object.entries(SHA.Variant)) {
                    if (shaVal === "SHA-1") {
                        continue;
                    }
                    for (const aesLength of [128, 192, 256]) {
                        const aesParams: params.EnforcedAesKeyGenParams = {
                            name: aesVal,
                            length: aesLength as any,
                        };
                        try {
                            let key = await HKDF.deriveKey(
                                { salt, info, hash: shaVal },
                                keyMaterial,
                                aesParams
                            );
                            expect(key).toMatchSnapshot(
                                `${aesKey}_${aesLength}_${shaKey}`
                            );
                        } catch (e) {
                            console.log(`${aesKey}_${aesLength}_${shaKey}`);
                        }
                    }
                }
            }

            const hmacParams: params.EnforcedHmacKeyGenParams = {
                name: Authentication.Code.HMAC,
                hash: SHA.Variant.SHA_512,
                length: 512,
            };
            let key = await HKDF.deriveKey(
                { salt, info, hash: SHA.Variant.SHA_512 },
                keyMaterial,
                hmacParams
            );
            expect(key).toMatchSnapshot("HMAC_SHA_512");
        });
    });
    describe("Proxied", () => {
        let keyMaterial: HkdfProxiedKeyMaterial,
            salt: Uint8Array,
            info: Uint8Array;
        beforeEach(async () => {
            keyMaterial = await HKDF.generateKeyMaterial(
                "raw",
                new TextEncoder().encode("password")
            );

            salt = await Random.Salt.generate();
            info = await Random.Salt.generate();
        });
        it("should derive bits", async () => {
            const bits = await keyMaterial.deriveBits(
                { salt, info, hash: SHA.Variant.SHA_512 },
                512
            );
            expect(bits.byteLength).toEqual(64);

            await expect(
                keyMaterial.deriveBits(
                    { salt, info, hash: SHA.Variant.SHA_512 },
                    511
                )
            ).rejects.toThrowError(RangeError);
        });
        it("should derive keys", async () => {
            for (const [aesKey, aesVal] of Object.entries(AES.Mode)) {
                for (const [shaKey, shaVal] of Object.entries(SHA.Variant)) {
                    if (shaVal === "SHA-1") {
                        continue;
                    }
                    for (const aesLength of [128, 192, 256]) {
                        const aesParams: params.EnforcedAesKeyGenParams = {
                            name: aesVal,
                            length: aesLength as any,
                        };
                        try {
                            let key = await keyMaterial.deriveKey(
                                { salt, info, hash: shaVal },
                                aesParams
                            );
                            expect(key).toMatchSnapshot(
                                `${aesKey}_${aesLength}_${shaKey}`
                            );
                        } catch (e) {
                            console.log(`${aesKey}_${aesLength}_${shaKey}`);
                        }
                    }
                }
            }

            const hmacParams: params.EnforcedHmacKeyGenParams = {
                name: Authentication.Code.HMAC,
                hash: SHA.Variant.SHA_512,
                length: 512,
            };
            let key = await keyMaterial.deriveKey(
                { salt, info, hash: SHA.Variant.SHA_512 },
                hmacParams
            );
            expect(key).toMatchSnapshot("HMAC_SHA_512");
        });
    });
});
