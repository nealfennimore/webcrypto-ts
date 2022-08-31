# Webcrypto TS

[![codecov](https://codecov.io/gh/nealfennimore/webcrypto-ts/branch/main/graph/badge.svg?token=DGUV5J0QPR)](https://codecov.io/gh/nealfennimore/webcrypto-ts)

An ESM based minimal typescript wrapper for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Supports both nodejs and browser Web Crypto.

Algorithms are split into their own modules, which enforces consumption of cryptographic materials from the same algorithm. API follows entirely with the Web Crypto API, but removes the need for specifying every argument (secure defaults and inferred key usages).

-   [Documentation](https://neal.codes/webcrypto-ts/) 📖
-   [Github](https://github.com/nealfennimore/webcrypto-ts) :octocat:

## Usage

```sh
npm i @nfen/webcrypto-ts
```
