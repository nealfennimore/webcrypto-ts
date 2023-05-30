/**
 * Code related to proxying CryptoKey and CryptoKeyPair
 * @module
 */

export interface ProxiedCryptoKey<T extends CryptoKey> {
    self: T;
    readonly algorithm: T["algorithm"];
    readonly extractable: T["extractable"];
    readonly type: T["type"];
    readonly usages: T["usages"];
}

export interface ProxiedCryptoKeyPair<
    TKeyPair extends CryptoKeyPair,
    TPrivKey extends CryptoKey,
    TProxPrivKey extends ProxiedCryptoKey<TPrivKey>,
    TPubKey extends CryptoKey,
    TProxPubKey extends ProxiedCryptoKey<TPubKey>
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
    TProxPrivKey extends ProxiedCryptoKey<TPrivKey>,
    TPubKey extends CryptoKey,
    TProxPubKey extends ProxiedCryptoKey<TPubKey>
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
                        return proxifyKey<TPrivKey, TProxPrivKey>(privHandler)(
                            target.privateKey as TPrivKey
                        );
                    case "publicKey":
                        return proxifyKey<TPubKey, TProxPubKey>(pubHandler)(
                            target.publicKey as TPubKey
                        );
                }

                return Reflect.get(target, prop);
            },
        });
    };
}
