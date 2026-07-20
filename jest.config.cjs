/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
    preset: "ts-jest",
    testEnvironment: "jsdom",
    setupFiles: ["<rootDir>/jest.setup.cjs"],
    snapshotSerializers: ["<rootDir>/jest.crypto-key-serializer.cjs"],
    testTimeout: 10000,
    globals: {
        "ts-jest": {
            encode: true,
            decode: true,
            useESM: true,
        },
    },
    collectCoverageFrom: ["./src/**/*.ts", "!**/__tests__/**"],
    extensionsToTreatAsEsm: [".ts"],
    moduleNameMapper: {
        "^(\\.{1,2}/.*)\\.js$": "$1",
    },
};
