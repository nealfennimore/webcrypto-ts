import { Alg as AES } from "../../aes/shared.js";
import { Alg as Authentication } from "../../hmac/index.js";
import * as params from "../../params.js";
import * as Random from "../../random.js";
import { Alg as SHA } from "../../sha/shared.js";
import * as KDF from "../index.js";
import type { Pbkdf2KeyMaterial } from "../shared.js";

const { PBKDF2 } = KDF;

describe("PBKDF2", () => {
    let keyMaterial: Pbkdf2KeyMaterial, salt: Uint8Array;
    beforeEach(async () => {
        keyMaterial = await PBKDF2.generateKeyMaterial(
            "raw",
            new TextEncoder().encode("password")
        );

        salt = await Random.Salt.generate();
    });
    it("should derive bits", async () => {
        const bits = await PBKDF2.deriveBits(
            { salt, hash: SHA.Variant.SHA_512 },
            keyMaterial,
            512
        );
        expect(bits.byteLength).toEqual(64);

        await expect(
            PBKDF2.deriveBits(
                { salt, hash: SHA.Variant.SHA_512 },
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
            name: Authentication.Code.HMAC,
            hash: SHA.Variant.SHA_512,
            length: 512,
        };
        let key = await PBKDF2.deriveKey(
            { salt, hash: SHA.Variant.SHA_512 },
            keyMaterial,
            hmacParams
        );
        expect(key).toMatchSnapshot("HMAC_SHA_512");
    });
});
