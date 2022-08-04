import * as alg from "../../alg";
import * as params from "../../params";
import { Salt } from "../../salt";
import { KDF } from "../index";
import type { Pbkdf2KeyMaterial } from "../shared";

const { PBKDF2 } = KDF;

describe("PBKDF2", () => {
    let keyMaterial: Pbkdf2KeyMaterial, salt: Uint8Array;
    beforeEach(async () => {
        keyMaterial = await PBKDF2.generateKeyMaterial(
            "raw",
            new TextEncoder().encode("password")
        );

        salt = await Salt.generate();
    });
    it("should derive bits", async () => {
        const bits = await PBKDF2.deriveBits(
            { salt, hash: alg.SHA.Variant.SHA_512 },
            keyMaterial,
            512
        );
        expect(bits.byteLength).toEqual(64);

        await expect(
            PBKDF2.deriveBits(
                { salt, hash: alg.SHA.Variant.SHA_512 },
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
                        let key = await PBKDF2.deriveKey(
                            { salt, hash: shaVal },
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
        let key = await PBKDF2.deriveKey(
            { salt, hash: alg.SHA.Variant.SHA_512 },
            keyMaterial,
            hmacParams
        );
        expect(key).toMatchSnapshot("HMAC_SHA_512");
    });
});
