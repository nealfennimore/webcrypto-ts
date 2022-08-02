export namespace AES {
    export enum Mode {
        AES_CBC = "AES-CBC",
        AES_CTR = "AES-CTR",
        AES_GCM = "AES-GCM",
        AES_KW = "AES-KW",
    }

    export type Modes = `${Mode}`;
}

export namespace SHA {
    export enum Variant {
        SHA_1 = "SHA-1",
        SHA_256 = "SHA-256",
        SHA_384 = "SHA-384",
        SHA_512 = "SHA-512",
    }
    export type Variants = `${Variant}`;
    export type SecureVariants = `${Exclude<Variant, Variant.SHA_1>}`;
}

export namespace RSA {
    export enum Variant {
        RSA_OAEP = "RSA-OAEP",
        RSA_PSS = "RSA-PSS",
        RSASSA_PKCS1_v1_5 = "RSASSA-PKCS1-v1_5",
    }
    export type Variants = `${Variant}`;
}

export namespace EC {
    export enum Variant {
        ECDSA = "ECDSA",
        ECDH = "ECDH",
    }
    export type Variants = `${Variant}`;

    export enum Curve {
        P_256 = "P-256",
        P_384 = "P-384",
        P_521 = "P-521",
    }

    export type Curves = `${Curve}`;
}

export namespace Authentication {
    export enum Code {
        HMAC = "HMAC",
    }
    export type Codes = `${Code}`;
}
export namespace KDF {
    export enum Variant {
        PBKDF2 = "PBKDF2",
        HKDF = "HKDF",
    }
    export type Variants = `${Variant}`;
}
