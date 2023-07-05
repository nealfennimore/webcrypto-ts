# Webcrypto TS

[![codecov](https://codecov.io/gh/nealfennimore/webcrypto-ts/branch/main/graph/badge.svg?token=DGUV5J0QPR)](https://codecov.io/gh/nealfennimore/webcrypto-ts)

A minimal ESM based, no dependency, typescript wrapper for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Supports both nodejs and browser Web Crypto.

Algorithms are split into their own modules, which enforces consumption of cryptographic materials from the same algorithm. API follows entirely with the Web Crypto API, but removes the need for specifying every argument (secure defaults and inferred key usages).

-   [Documentation](https://neal.codes/webcrypto-ts/) 📖
-   [Github](https://github.com/nealfennimore/webcrypto-ts) :octocat:
-   [NPM](https://www.npmjs.com/package/@nfen/webcrypto-ts)

## Install

```sh
npm i @nfen/webcrypto-ts
```

## Examples

Many more examples in the [Documentation](https://neal.codes/webcrypto-ts/).

### ECDSA

```ts
import * as ECDSA from "@nfen/webcrypto-ts/lib/ec/ecdsa";
const keyPair = await ECDSA.generateKey();

const message = new TextEncoder().encode("a message");
const signature = await keyPair.privateKey.sign({ hash: "SHA-512" }, message);

const pubJwk = await keyPair.publicKey.exportKey("jwk");
const publicKey = await ECDSA.importKey(
    "jwk",
    pubJwk,
    { namedCurve: "P-512" },
    true,
    ["verify"]
);

const isVerified = await publicKey.verify(
    { hash: "SHA-512" },
    signature,
    message
);
```

### RSA-OAEP

```ts
import * as RSA_OAEP from "@nfen/webcrypto-ts/lib/rsa/rsa_oaep";
import * as AES_CBC from "@nfen/webcrypto-ts/lib/aes/aes_cbc";
import * as Random from "@nfen/webcrypto-ts/lib/random";

const kek = await RSA_OAEP.generateKey(
    {
        hash: "SHA-512",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    true,
    ["wrapKey", "unwrapKey"]
);
const dek = await AES_CBC.generateKey();
const label = await Random.getValues(8);
const wrappedCbcKey = await kek.publicKey.wrapKey("raw", dek.self, { label });
```

### AES-GCM

```ts
import * as AES_GCM from "@nfen/webcrypto-ts/lib/aes/aes_gcm";
import { IV } from "@nfen/webcrypto-ts/lib/random";

const iv = await IV.generate();
const key = await AES_GCM.generateKey();
const message = "a message";
const cipherText = await key.encrypt(
    { iv },
    new TextEncoder().encode("a message")
);
console.assert(
    new TextDecoder().decode(await key.decrypt({ iv }, message)) === message
);
```
