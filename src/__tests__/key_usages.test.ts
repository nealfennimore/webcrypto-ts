import * as KeyUsages from "../key_usages.js";

describe("KeyUsages", () => {
    it("should throw when no key usage algorithm", async () => {
        expect(() => KeyUsages.getKeyUsagePairsByAlg("unknown")).toThrow();
    });
});
