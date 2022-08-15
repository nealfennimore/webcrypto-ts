# Webcrypto TS

[![codecov](https://codecov.io/gh/nealfennimore/webcrypto-ts/branch/main/graph/badge.svg?token=DGUV5J0QPR)](https://codecov.io/gh/nealfennimore/webcrypto-ts)

An ESM based typescript wrapper for Web Crypto. Supports both nodejs webcrypto and browser webcrypto in the same package.

[Documentation](https://neal.codes/webcrypto-ts/) :book:

## Usage

### Node

```js
import { AES_GCM } from "@nfen/webcrypto-ts/lib/aes";
import { IV } from "@nfen/webcrypto-ts/lib/random";

(async function () {
    k = await AES_GCM.generateKey();
    const iv = await IV.generate();

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const ciphertext = await AES_GCM.encrypt(
        { iv },
        k,
        encoder.encode("message")
    );
    const plaintext = await AES_GCM.decrypt({ iv }, k, ciphertext);

    console.log(decoder.decode(plaintext) === "message");
})();
```

### Browser

```html
<script type="module">
    import("/lib/index.js").then(async (WebCrypto) => {
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();

        const key = await WebCrypto.AES.AES_GCM.generateKey();
        const iv = await WebCrypto.Random.IV.generate();
        const message = encoder.encode("my message");

        const ciphertext = await WebCrypto.AES.AES_GCM.encrypt(
            { iv },
            key,
            message
        );
        console.log("ciphertext:", decoder.decode(ciphertext));

        const plaintext = await WebCrypto.AES.AES_GCM.decrypt(
            { iv },
            key,
            ciphertext
        );
        console.log("plaintext:", decoder.decode(plaintext));

        console.assert(decoder.decode(plaintext) === decoder.decode(message));
    });
</script>
```
