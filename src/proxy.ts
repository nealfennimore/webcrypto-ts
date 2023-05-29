/**
 * Code related to proxying CryptoKey and CryptoKeyPair
 * @module
 */

export interface ProxiedPubCryptoKey<T extends CryptoKey> {
    self: T;
}

export interface ProxiedPrivCryptoKey<T extends CryptoKey> {
    self: T;
}

export interface ProxiedCryptoKeyPair<
    TKeyPair extends CryptoKeyPair,
    TPrivKey extends CryptoKey,
    TProxPrivKey extends ProxiedPrivCryptoKey<TPrivKey>,
    TPubKey extends CryptoKey,
    TProxPubKey extends ProxiedPubCryptoKey<TPubKey>
> {
    self: TKeyPair;
    privateKey: TProxPrivKey;
    publicKey: TProxPubKey;
}
export function proxifyPubKey<
    TPubKey extends CryptoKey,
    TProxPubKey extends ProxiedPubCryptoKey<TPubKey>
>(handler: ProxyHandler<TPubKey>) {
    return function _proxifyPubKey(privKey: TPubKey) {
        return new Proxy<TPubKey, TProxPubKey>(privKey, handler);
    };
}

export function proxifyPrivKey<
    TPrivKey extends CryptoKey,
    TProxPrivKey extends ProxiedPrivCryptoKey<TPrivKey>
>(handler: ProxyHandler<TPrivKey>) {
    return function _proxifyPrivKey(privKey: TPrivKey) {
        return new Proxy<TPrivKey, TProxPrivKey>(privKey, handler);
    };
}

export interface ProxyKeyPairHandlers<
    TPrivKey extends CryptoKey,
    TPubKey extends CryptoKey
> {
    privHandler: ProxyHandler<TPrivKey>;
    pubHandler: ProxyHandler<TPubKey>;
}

export function proxifyKeyPair<
    TKeyPair extends CryptoKeyPair,
    TPrivKey extends CryptoKey,
    TProxPrivKey extends ProxiedPrivCryptoKey<TPrivKey>,
    TPubKey extends CryptoKey,
    TProxPubKey extends ProxiedPubCryptoKey<TPubKey>
>({ privHandler, pubHandler }: ProxyKeyPairHandlers<TPrivKey, TPubKey>) {
    return function _proxifyKeyPair(keyPair: TKeyPair) {
        return new Proxy<
            TKeyPair,
            ProxiedCryptoKeyPair<
                TKeyPair,
                TPrivKey,
                TProxPrivKey,
                TPubKey,
                TProxPubKey
            >
        >(keyPair, {
            get(target: TKeyPair, prop: string) {
                switch (prop) {
                    case "self":
                        return target;
                    case "privateKey":
                        return proxifyPrivKey<TPrivKey, TProxPrivKey>(
                            privHandler
                        )(target.privateKey as TPrivKey);
                    case "publicKey":
                        return proxifyPubKey<TPubKey, TProxPubKey>(pubHandler)(
                            target.publicKey as TPubKey
                        );
                }

                return Reflect.get(target, prop);
            },
        });
    };
}
