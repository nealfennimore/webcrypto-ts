/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  setupFiles: ['<rootDir>/jest.setup.js'],
  testTimeout: 10000,
  globals: {
    'ts-jest': {
        "encode": true,
        "decode": true,
    }
  }
};