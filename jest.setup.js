const { TextDecoder, TextEncoder } = require('util');
const { webcrypto } = require('node:crypto')

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.crypto = webcrypto;
