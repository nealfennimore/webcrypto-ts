import * as alg from "../../alg.js";
import * as params from "../../params.js";
import { Salt } from "../../salt.js";
import * as KDF from "../index.js";
import type { HkdfKeyMaterial } from "../shared.js";

const { HKDF } = KDF;
describe("HKDF", () => {
    let keyMaterial: HkdfKeyMaterial, salt: Uint8Array, info: Uint8Array;
    beforeEach(async () => {
        keyMaterial = await HKDF.generateKeyMaterial(
            "raw",
            new TextEncoder().encode("password")
        );

        salt = await Salt.generate();
        info = await Salt.generate();
    });
    it("should derive bits", async () => {
        const bits = await HKDF.deriveBits(
            { salt, info, hash: alg.SHA.Variant.SHA_512 },
            keyMaterial,
            512
        );
        expect(bits.byteLength).toEqual(64);

        await expect(
            HKDF.deriveBits(
                { salt, info, hash: alg.SHA.Variant.SHA_512 },
                keyMaterial,
                511
            )
        ).rejects.toThrowError(RangeError);
    });
    it("should derive keys", async () => {
        for (const [aesKey, aesVal] of Object.entries(alg.AES.Mode)) {
            for (const [shaKey, shaVal] of Object.entries(alg.SHA.Variant)) {
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
            name: alg.Authentication.Code.HMAC,
            hash: alg.SHA.Variant.SHA_512,
            length: 512,
        };
        let key = await HKDF.deriveKey(
            { salt, info, hash: alg.SHA.Variant.SHA_512 },
            keyMaterial,
            hmacParams
        );
        expect(key).toMatchSnapshot("HMAC_SHA_512");
    });
});
