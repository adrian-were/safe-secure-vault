// secure-vault.js
const {
    subtle,
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
} = require('./lib');

const PBKDF2_ITERATIONS = 100000;
const MAX_NOTE_LENGTH = 64; // Maximum secret note/password length (64 chars)
const SALT_BYTE_LEN = 16;   // 128-bit salt
const IV_BYTE_LEN = 12;     // 96-bit IV recommended for AES-GCM
const AUTH_CONSTANT = "VAULT_MASTER_KEY_AUTH_CHECK";

class SecureVault {
    /**
     * 4.3 constructor(...)
     * Initializes the in-memory state of the vault. Run-time: O(1)
     */
    constructor(kvs, salt, hmacKey, aesKey, authTag) {
        this.data = {
            kvs: kvs || {},       // Key-Value Store (required field 'kvs' for serialization)
            salt: salt,           // Base64 encoded 128-bit salt
            authTag: authTag      // Base64 HMAC tag to verify master password on load()
        };
        this.secrets = {
            hmacKey: hmacKey,     // CryptoKey for HMAC-SHA-256 (domain/contact lookup)
            aesKey: aesKey        // CryptoKey for AES-GCM (secret note/password encryption)
        };
    }

    /**
     * Internal helper: Derives the HMAC sub-key and AES-GCM sub-key from a master password
     * and salt using a single call to PBKDF2 followed by HMAC as a PRF.
     */
    static async _deriveKeys(password, saltBuffer) {
        // 1. Import raw master password for PBKDF2
        const rawMasterKey = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        // 2. Run PBKDF2 ONCE to derive the master HMAC key (k)
        const masterHmacKey = await subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBuffer,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            rawMasterKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            false,
            ["sign"]
        );

        // 3. Use Master HMAC key as a PRF at two distinct constants to get raw sub-key material
        const hmacKeyMaterial = await subtle.sign(
            "HMAC",
            masterHmacKey,
            stringToBuffer("SUBKEY_1_HMAC_DOMAIN_LOOKUP")
        );

        const aesKeyMaterial = await subtle.sign(
            "HMAC",
            masterHmacKey,
            stringToBuffer("SUBKEY_2_AES_GCM_ENCRYPTION")
        );

        // 4. Import Sub-key 1 as an HMAC CryptoKey
        const hmacKey = await subtle.importKey(
            "raw",
            hmacKeyMaterial,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign", "verify"]
        );

        // 5. Import Sub-key 2 as an AES-GCM CryptoKey
        const aesKey = await subtle.importKey(
            "raw",
            aesKeyMaterial,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        // 6. Compute an authentication tag so load() can verify the master password in O(1)
        const authTagBuffer = await subtle.sign(
            "HMAC",
            hmacKey,
            stringToBuffer(AUTH_CONSTANT)
        );

        return {
            hmacKey,
            aesKey,
            authTag: encodeBuffer(authTagBuffer)
        };
    }

    /**
     * Internal helper: Pads a string to exactly MAX_NOTE_LENGTH (64 bytes) to hide length.
     * Format: [1 byte length prefix] + [string bytes] + [zero padding bytes] = 65 bytes total.
     */
    static _padValue(value) {
        const strBuf = stringToBuffer(value);
        if (strBuf.length > MAX_NOTE_LENGTH) {
            throw new Error(`Value exceeds maximum allowed length of ${MAX_NOTE_LENGTH} characters.`);
        }
        const padded = Buffer.alloc(MAX_NOTE_LENGTH + 1, 0);
        padded.writeUInt8(strBuf.length, 0); // Store exact length in byte 0
        strBuf.copy(padded, 1);              // Copy actual characters starting at byte 1
        return padded;
    }

    /**
     * Internal helper: Removes padding and restores original string using the length prefix byte.
     */
    static _unpadValue(paddedArrayBuffer) {
        const buf = Buffer.from(paddedArrayBuffer);
        const actualLength = buf.readUInt8(0);
        if (actualLength > MAX_NOTE_LENGTH || actualLength + 1 > buf.length) {
            throw new Error("Invalid padding detected during decryption.");
        }
        return bufferToString(buf.subarray(1, 1 + actualLength));
    }

    /**
     * 4.1 static async init(password)
     * Creates a new empty SecureVault protected by the master password. Run-time: O(1)
     */
    static async init(password) {
        const saltBuffer = getRandomBytes(SALT_BYTE_LEN);
        const { hmacKey, aesKey, authTag } = await SecureVault._deriveKeys(password, saltBuffer);
        return new SecureVault({}, encodeBuffer(saltBuffer), hmacKey, aesKey, authTag);
    }

    /**
     * 4.2 static async load(password, repr, trustedDataCheck)
     * Loads the vault state from a serialized JSON string and verifies integrity. Run-time: O(n)
     */
    static async load(password, repr, trustedDataCheck) {
        // 1. Defend against Rollback/Tampering Attack if trustedDataCheck is provided
        if (trustedDataCheck !== undefined) {
            const computedHashBuf = await subtle.digest("SHA-256", stringToBuffer(repr));
            const computedHash = encodeBuffer(computedHashBuf);
            if (computedHash !== trustedDataCheck) {
                throw new Error("Tampering or Rollback Attack detected: SHA-256 checksum mismatch!");
            }
        }

        // 2. Parse the JSON representation
        let parsed;
        try {
            parsed = JSON.parse(repr);
        } catch (err) {
            throw new Error("Invalid JSON representation.");
        }

        if (!parsed.kvs || !parsed.salt || !parsed.authTag) {
            throw new Error("Malformed vault serialization.");
        }

        // 3. Re-derive keys using the stored salt and provided password
        const saltBuffer = decodeBuffer(parsed.salt);
        const { hmacKey, aesKey, authTag } = await SecureVault._deriveKeys(password, saltBuffer);

        // 4. Verify that the master password is correct
        if (authTag !== parsed.authTag) {
            throw new Error("Authentication failed: Invalid master password!");
        }

        return new SecureVault(parsed.kvs, parsed.salt, hmacKey, aesKey, parsed.authTag);
    }

    /**
     * 4.4 async dump()
     * Returns [repr, sha256_hash] for simulated disk & trusted storage. Run-time: O(n)
     */
    async dump() {
        const repr = JSON.stringify(this.data);
        const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
        const sha256Hash = encodeBuffer(hashBuffer);
        return [repr, sha256Hash];
    }

    /**
     * 4.5 async set(name, value)
     * Inserts or updates a contact/domain and its secret note/password in O(1) time.
     */
    async set(name, value) {
        // 1. Compute HMAC of the domain/contact name for obfuscated O(1) key lookup
        const hmacBuf = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
        const obfuscatedKey = encodeBuffer(hmacBuf);

        // 2. Pad the secret value to fixed length so ciphertext doesn't leak password length
        const paddedPlaintext = SecureVault._padValue(value);

        // 3. Generate a fresh 96-bit random IV for AES-GCM
        const iv = getRandomBytes(IV_BYTE_LEN);

        // 4. Encrypt with AES-GCM, binding the ciphertext to `obfuscatedKey` via additionalData
        //    to defend against Swap Attacks!
        const ciphertextBuf = await subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: stringToBuffer(obfuscatedKey)
            },
            this.secrets.aesKey,
            paddedPlaintext
        );

        // 5. Store IV and Ciphertext in the KVS
        this.data.kvs[obfuscatedKey] = {
            iv: encodeBuffer(iv),
            ct: encodeBuffer(ciphertextBuf)
        };
    }

    /**
     * 4.6 async get(name)
     * Fetches and decrypts the secret value for `name` in O(1) time, or returns null if not found.
     */
    async get(name) {
        const hmacBuf = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
        const obfuscatedKey = encodeBuffer(hmacBuf);

        if (!Object.prototype.hasOwnProperty.call(this.data.kvs, obfuscatedKey)) {
            return null;
        }

        const record = this.data.kvs[obfuscatedKey];
        if (!record || !record.iv || !record.ct) {
            throw new Error("Tampering detected: Malformed record in KVS.");
        }

        try {
            // Decrypt and verify that additionalData matches the key being queried (Swap Defense)
            const decryptedPaddedBuf = await subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: decodeBuffer(record.iv),
                    additionalData: stringToBuffer(obfuscatedKey)
                },
                this.secrets.aesKey,
                decodeBuffer(record.ct)
            );

            return SecureVault._unpadValue(decryptedPaddedBuf);
        } catch (err) {
            // AES-GCM throws if ciphertext was modified OR if records were swapped between keys
            throw new Error("Tampering or Swap Attack detected: Decryption authentication failed!");
        }
    }

    /**
     * 4.7 async remove(name)
     * Removes the record from the KVS in O(1) time. Returns true if found & deleted, false otherwise.
     */
    async remove(name) {
        const hmacBuf = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
        const obfuscatedKey = encodeBuffer(hmacBuf);

        if (Object.prototype.hasOwnProperty.call(this.data.kvs, obfuscatedKey)) {
            delete this.data.kvs[obfuscatedKey];
            return true;
        }
        return false;
    }
}

module.exports = { SecureVault };