// lib.js
const crypto = require('crypto');
const subtle = crypto.webcrypto.subtle;

/**
 * Converts a plaintext string into a Buffer for SubtleCrypto functions.
 */
function stringToBuffer(str) {
    return Buffer.from(str, 'utf-8');
}

/**
 * Converts a Buffer/ArrayBuffer from SubtleCrypto back into a UTF-8 string.
 */
function bufferToString(buf) {
    return Buffer.from(buf).toString('utf-8');
}

/**
 * Converts a Buffer/ArrayBuffer into a Base64-encoded string for JSON serialization.
 */
function encodeBuffer(buf) {
    return Buffer.from(buf).toString('base64');
}

/**
 * Converts a Base64-encoded string back into a Buffer for SubtleCrypto functions.
 */
function decodeBuffer(base64) {
    return Buffer.from(base64, 'base64');
}

/**
 * Generates cryptographically strong random bytes of the specified length.
 */
function getRandomBytes(len) {
    return crypto.randomBytes(len);
}

module.exports = {
    subtle,
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
};