/**
 * Code related to proxying CryptoKey and CryptoKeyPair
 * @module
 */

export interface ProxiedPubCryptoKey<T extends CryptoKey> {
    self: T;
    verify: Function;
}

export interface ProxiedPrivCryptoKey<T extends CryptoKey> {
    self: T;
    sign: Function;
}

export interface ProxiedCryptoKeyPair<
    TKeyPair extends CryptoKeyPair,
    TPrivKey extends CryptoKey,
    TPubKey extends CryptoKey
> {
    self: TKeyPair;
    privateKey: ProxiedPrivCryptoKey<TPrivKey>;
    publicKey: ProxiedPubCryptoKey<TPubKey>;
}

export function proxifyPubKey<TPubKey extends CryptoKey>(pubKey: TPubKey) {
    const handler = {
        get(target: TPubKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "verify":
                    return () => console.log("verify called");
            }

            return Reflect.get(target, prop);
        },
    };

    return new Proxy<TPubKey, ProxiedPubCryptoKey<TPubKey>>(pubKey, handler);
}

export function proxifyPrivKey<TPrivKey extends CryptoKey>(privKey: TPrivKey) {
    const handler = {
        get(target: TPrivKey, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "sign":
                    return () => console.log("sign called");
            }

            return Reflect.get(target, prop);
        },
    };

    return new Proxy<TPrivKey, ProxiedPrivCryptoKey<TPrivKey>>(
        privKey,
        handler
    );
}

export function proxifyKeyPair<
    TKeyPair extends CryptoKeyPair,
    TPrivKey extends CryptoKey,
    TPubKey extends CryptoKey
>(keyPair: TKeyPair) {
    return new Proxy<
        TKeyPair,
        ProxiedCryptoKeyPair<TKeyPair, TPrivKey, TPubKey>
    >(keyPair, {
        get(target: TKeyPair, prop: string) {
            switch (prop) {
                case "self":
                    return target;
                case "privateKey":
                    return proxifyPrivKey<TPrivKey>(
                        target.privateKey as TPrivKey
                    );
                case "publicKey":
                    return proxifyPubKey<TPubKey>(target.publicKey as TPubKey);
            }

            return Reflect.get(target, prop);
        },
    });
}
