const { TextDecoder, TextEncoder } = require('util');
const { webcrypto } = require('node:crypto')

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.crypto = webcrypto;



global.encode = (...args)=>new TextEncoder().encode(...args);
global.decode = (...args)=>new TextDecoder().decode(...args);