# Webcrypto TS

[![Test](https://github.com/nealfennimore/webcrypto-ts/actions/workflows/test.yml/badge.svg)](https://github.com/nealfennimore/webcrypto-ts/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/nealfennimore/webcrypto-ts/branch/main/graph/badge.svg?token=DGUV5J0QPR)](https://codecov.io/gh/nealfennimore/webcrypto-ts) [![Bundle Size](https://deno.bundlejs.com/badge?q=@nfen/webcrypto-ts@0.2.3)](https://deno.bundlejs.com/badge?q=@nfen/webcrypto-ts@0.2.3)

A minimal ESM based, no dependency, typescript wrapper for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Supports both nodejs and browser Web Crypto.

Algorithms are split into their own modules, which enforces consumption of cryptographic materials from the same algorithm. API follows entirely with the Web Crypto API, but removes the need for specifying every argument (secure defaults and inferred key usages). Keys are also [proxied](#proxied-keys-and-methods) to make it easier to use with cryptographic operations.

- [Documentation](https://webcrypto.neal.codes) 📖
- [Github](https://github.com/nealfennimore/webcrypto-ts) :octocat:
- [NPM](https://www.npmjs.com/package/@nfen/webcrypto-ts)

## Install

```sh
npm i @nfen/webcrypto-ts
```

## Proxied Keys and Methods

All generated keys are wrapped in a [Proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy) object, which allows for executing methods specific to each key within a [small wrapper](https://github.com/nealfennimore/webcrypto-ts/blob/main/src/proxy.ts).

For example, we can generate an ECDSA keypair and `sign` directly off the `privateKey`.

```ts
import * as ECDSA from "@nfen/webcrypto-ts/lib/ec/ecdsa";
const keyPair = await ECDSA.generateKeyPair();
const message = new TextEncoder().encode("a message");
const signature = await keyPair.privateKey.sign({ hash: "SHA-512" }, message);
```

We can still use the WebCrypto based API too. Access any CryptoKey or CryptoKeyPair by using `self` on the key.

```ts
const signature = await ECDSA.sign(keyPair.privateKey.self, { hash: "SHA-512" }, message);
```

## Examples

Many more examples in the [Documentation](https://webcrypto.neal.codes).

### ECDSA

```ts
import * as ECDSA from "@nfen/webcrypto-ts/lib/ec/ecdsa";
const keyPair = await ECDSA.generateKeyPair();

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

### Ed25519

```ts
import * as Ed25519 from "@nfen/webcrypto-ts/lib/curve25519/ed25519";
const keyPair = await Ed25519.generateKeyPair();

const message = new TextEncoder().encode("a message");
const signature = await keyPair.privateKey.sign(message);

const pubJwk = await keyPair.publicKey.exportKey("jwk");
const publicKey = await Ed25519.importKey("jwk", pubJwk, true, ["verify"]);

const isVerified = await publicKey.verify(signature, message);
```

### X25519

```ts
import * as X25519 from "@nfen/webcrypto-ts/lib/curve25519/x25519";

const keyPair = await X25519.generateKeyPair();
const otherKeyPair = await X25519.generateKeyPair();

const key = await keyPair.privateKey.deriveKey(
    { public: otherKeyPair.publicKey.self },
    {
        name: "AES-GCM",
        length: 256,
    }
);
```

### ML-DSA (post-quantum signatures)

Requires Node.js `>= 24.7.0` (or a browser implementing [Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/)). Variants: `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.

```ts
import * as ML_DSA_65 from "@nfen/webcrypto-ts/lib/ml_dsa/ml_dsa_65";

const keyPair = await ML_DSA_65.generateKeyPair();

const message = new TextEncoder().encode("a message");
const signature = await keyPair.privateKey.sign(message);

const pubKeyBytes = await keyPair.publicKey.exportKey("raw-public");
const publicKey = await ML_DSA_65.importKey("raw-public", pubKeyBytes, true, [
    "verify",
]);

const isVerified = await publicKey.verify(signature, message);
```

### ML-KEM (post-quantum key encapsulation)

Requires Node.js `>= 24.7.0`. Variants: `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`.

```ts
import * as ML_KEM_768 from "@nfen/webcrypto-ts/lib/ml_kem/ml_kem_768";

const keyPair = await ML_KEM_768.generateKeyPair();

// Sender: encapsulate a shared AES key for the recipient
const { sharedKey, ciphertext } = await keyPair.publicKey.encapsulateKey({
    name: "AES-GCM",
    length: 256,
});

// Recipient: recover the same AES key from the ciphertext
const recovered = await keyPair.privateKey.decapsulateKey(ciphertext, {
    name: "AES-GCM",
    length: 256,
});

// Or work with raw shared secrets (32 bytes) instead of CryptoKeys
const bits = await keyPair.publicKey.encapsulateBits();
const secret = await keyPair.privateKey.decapsulateBits(bits.ciphertext);
```

### KMAC

Requires Node.js `>= 24.8.0`. Variants: `KMAC128`, `KMAC256`.

```ts
import * as KMAC256 from "@nfen/webcrypto-ts/lib/kmac/kmac_256";

const key = await KMAC256.generateKey();

const message = new TextEncoder().encode("a message");
const customization = new TextEncoder().encode("my-protocol");
// outputLength is in bits — a 256-bit (32-byte) MAC
const signature = await key.sign({ outputLength: 256, customization }, message);

const isVerified = await key.verify(
    { outputLength: 256, customization },
    signature,
    message
);
```

### Ed448 / X448

Same API as [Ed25519](#ed25519) and [X25519](#x25519), from `@nfen/webcrypto-ts/lib/curve448/ed448` and `@nfen/webcrypto-ts/lib/curve448/x448`. `Ed448.sign`/`verify` additionally accept an optional `{ context }` (non-empty context requires Node.js `>= 24.8.0`).

### RSA-OAEP

```ts
import * as RSA_OAEP from "@nfen/webcrypto-ts/lib/rsa/rsa_oaep";
import * as AES_CBC from "@nfen/webcrypto-ts/lib/aes/aes_cbc";
import * as Random from "@nfen/webcrypto-ts/lib/random";

const kek = await RSA_OAEP.generateKeyPair(
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
    new TextDecoder().decode(await key.decrypt({ iv }, cipherText)) === message
);
```
