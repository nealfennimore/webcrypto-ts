/**
 * Node 22+ keeps CryptoKey state in internal slots exposed via prototype
 * getters, which pretty-format ignores — keys would snapshot as `CryptoKey {}`.
 * Serialize the public getters instead.
 */
const { types } = require("node:util");

module.exports = {
    test(val) {
        // types.isCryptoKey misses proxied keys (a Proxy hides the native
        // internals), so fall back to the constructor name read through the
        // proxy's get handler.
        if (types.isCryptoKey(val)) {
            return true;
        }
        return (
            typeof val === "object" &&
            val !== null &&
            val.constructor?.name === "CryptoKey"
        );
    },
    serialize(val, config, indentation, depth, refs, printer) {
        return (
            "CryptoKey " +
            printer(
                {
                    algorithm: val.algorithm,
                    extractable: val.extractable,
                    type: val.type,
                    usages: val.usages,
                },
                config,
                indentation,
                depth,
                refs
            )
        );
    },
};
