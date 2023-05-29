/**
 * Code related to proxying CryptoKey and CryptoKeyPair
 * @module
 */

export interface ProxiedCryptoKey<T extends CryptoKey> {
    self: T;
}
export interface ProxiedPubCryptoKey<T extends CryptoKey>
    extends ProxiedCryptoKey<T> {}

export interface ProxiedPrivCryptoKey<T extends CryptoKey>
    extends ProxiedCryptoKey<T> {}

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
export function proxifyKey<
    TKey extends CryptoKey,
    TProxKey extends ProxiedCryptoKey<TKey>
>(handler: ProxyHandler<TKey>) {
    return function _proxifyKey(key: TKey) {
        return new Proxy<TKey, TProxKey>(key, handler);
    };
}

export const proxifyPubKey = proxifyKey;
export const proxifyPrivKey = proxifyKey;

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
