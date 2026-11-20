# Secure Contact & Note Vault (ICS 3201 — Computer Security)

A cryptographic key-value vault inspired by modern password managers (such as Bitwarden and 1Password) and built according to the **ICS 3201 Project 1** security specifications. It protects sensitive contacts, notes, and passwords at rest using the **Web Crypto API (`SubtleCrypto`)** with zero external cryptographic dependencies.

This project includes three ways to interact with the vault:
1. **Interactive Web UI (`secure-vault.html`)** — A browser-based dashboard with a live obfuscated KVS inspector and an adversary attack simulator.
2. **Automated Security Test Suite (`test-vault.js`)** — Verifies all API methods and simulates length-leakage, swap, and rollback attacks.
3. **Interactive Terminal CLI (`cli.js`)** — A Node.js command-line interface with simulated disk persistence (`vault-disk.json` and `trusted-hash.txt`).

---

## 1. VS Code Project Structure

Create a folder named `secure-vault-project` in VS Code and place the files inside as shown below:

```text
secure-vault-project/
├── secure-vault.html   # Interactive Web UI (HTML + Tailwind CSS + Web Crypto API)
├── lib.js              # Node.js SubtleCrypto & Base64/Buffer conversion helpers
├── secure-vault.js     # Core Node.js SecureVault library (init, load, dump, set, get, remove)
├── test-vault.js       # Automated unit & cryptographic attack test suite
├── cli.js              # Interactive Node.js terminal application
├── package.json        # npm scripts for quick execution in VS Code
└── README.md           # Project documentation
```

---

## 2. How to Run in VS Code

### Prerequisites
* **Node.js (v16 or newer)** for running the CLI and test suite (`node -v`).
* A modern web browser (Chrome, Edge, Firefox, or Safari) for the Web UI.

### Option A: Run the Interactive Web UI (`secure-vault.html`)
Because the browser's `window.crypto.subtle` API requires a secure context (`localhost` or HTTPS), run `secure-vault.html` using one of these methods:

* **Method 1 (VS Code Live Server — Recommended):**
  1. Install the **Live Server** extension in VS Code.
  2. Right-click `secure-vault.html` in the VS Code Explorer and select **"Open with Live Server"**.
* **Method 2 (VS Code Terminal):**
  ```bash
  npm run ui
  ```
  Then open the local URL printed in the terminal (e.g., `http://localhost:3000/secure-vault.html`).

### Option B: Run the Automated Security Tests
Open the integrated terminal in VS Code (`Ctrl + ~`) and run:
```bash
npm test
```
*(Or directly via `node test-vault.js`)*

### Option C: Run the Interactive Terminal CLI
```bash
npm run cli
```
*(Or directly via `node cli.js`)*

---

## 3. How the Cryptography Works

The vault is designed to maintain **confidentiality**, **integrity**, and **domain privacy** even if an adversary gains full read/write access to the serialized JSON database on disk.

### A. Key Derivation (`PBKDF2` + `HMAC` as PRF)
1. When a new vault is initialized, a random **128-bit salt** is generated to defeat offline dictionary and rainbow table attacks.
2. **PBKDF2-SHA256** (100,000 iterations) is executed **once** on the master password and salt to produce a 256-bit Master Key $k$.
3. Because PBKDF2 is intentionally slow, $k$ is used as an **HMAC-SHA256 Pseudorandom Function (PRF)** evaluated at two distinct domain-separation constants to derive two independent sub-keys:
   * $k_{\text{hmac}}$: Used exclusively for hashing lookup keys (domains/contacts) and computing the master password verification tag (`authTag`).
   * $k_{\text{aes}}$: Used exclusively for **AES-GCM** encryption and decryption of secret values.
4. Neither the master password nor any derived secret key is ever written to the serialized JSON database.

### B. Domain & Contact Privacy (`HMAC-SHA256`)
Plaintext domain/contact names are never stored in the Key-Value Store (KVS). Instead, each lookup key $x$ is stored as its deterministic Base64-encoded HMAC:
$$K_{\text{obfuscated}} = \text{Base64}\big(\text{HMAC}(k_{\text{hmac}}, x)\big)$$
This hides which websites or contacts exist in the vault while preserving **$O(1)$** lookup speed.

### C. Password Length Hiding (Fixed 65-Byte Padding)
Raw encryption leaks the length of the plaintext. Before encrypting any secret (up to 64 UTF-8 bytes), the vault pads every value to a uniform **65-byte** buffer:
```text
[ 1 byte: actual UTF-8 byte length ] + [ N bytes: secret data ] + [ (64 - N) bytes: 0x00 padding ]
```
As a result, a 4-character PIN and a 64-character passphrase produce ciphertexts of the **exact same length** (108 Base64 characters including the 16-byte AES-GCM authentication tag).

### D. Authenticated Encryption & Swap Attack Defense (`AES-GCM` + AAD)
Each record is encrypted individually with **AES-GCM** using a fresh random **96-bit IV**.
* **Swap Attack Threat:** An adversary with disk access could swap the encrypted `{iv, ct}` values of `www.google.com` and `www.evil.com`, tricking the user into sending their Google password to an evil site.
* **Defense:** During encryption and decryption, the vault binds each ciphertext to its specific lookup key by passing $K_{\text{obfuscated}}$ as **Authenticated Additional Data (`additionalData` / AAD)** to AES-GCM. If two records are swapped—or if a single bit of ciphertext is modified—AES-GCM authentication fails and immediately throws a cryptographic exception. This defense works **independently** of the whole-database SHA-256 hash.

### E. Rollback Attack Defense (`SHA-256` Checksum)
* **Rollback Threat:** An adversary could replace an updated database file with an older, previously valid snapshot to revert a user's password to an older compromised one.
* **Defense:** Calling `dump()` computes a **SHA-256** digest of the entire serialized JSON string. This checksum is meant to be stored on trusted storage (inaccessible to the disk adversary). When `load(password, repr, trustedDataCheck)` is called, the vault hashes the incoming JSON and rejects it if the digest does not match `trustedDataCheck`.

---

## 4. Core API & Time Complexity

Let $n$ be the number of records stored in the vault:

| Method | Time Complexity | Description |
| :--- | :---: | :--- |
| `SecureVault.init(password)` | $O(1)$ | Generates a 128-bit salt, derives keys via PBKDF2 + HMAC, and returns a new vault. |
| `SecureVault.load(password, repr, trustedDataCheck)` | $O(n)$ | Verifies optional SHA-256 checksum, parses JSON, re-derives keys, and verifies the master password. |
| `vault.dump()` | $O(n)$ | Serializes `{ kvs, salt, authTag }` to JSON and returns `[jsonString, sha256Hash]`. |
| `vault.set(name, value)` | $O(1)$ | HMACs `name`, pads `value` to 65 bytes, encrypts with AES-GCM + AAD, and stores `{ iv, ct }`. |
| `vault.get(name)` | $O(1)$ | Looks up HMAC of `name`, verifies AES-GCM tag & AAD, unpads, and returns the secret (or `null`). |
| `vault.remove(name)` | $O(1)$ | Deletes the record matching the HMAC of `name` and returns `true` or `false`. |

---

## 5. Live Security Demo Guide (Using `secure-vault.html`)

1. **Initialize:** Click **Quick-fill Demo Password** and click **Initialize Vault (PBKDF2)**.
2. **Length Hiding & Domain Obfuscation:** Click **+ Seed 3 Sample Records**. Observe in the **Live Obfuscated KVS Inspector** that the names are hashed via HMAC and all three ciphertexts—despite having very different plaintext lengths—are identically **108 characters long**.
3. **Swap Attack Defense:** Click **Simulate Swap Attack**, then try to retrieve `John Doe` or `www.google.com`. The vault immediately raises a **Cryptographic Exception Caught** alert because the AES-GCM `additionalData` binding fails.
4. **Rollback Attack Defense:** Click **Save Snapshot for Rollback Test**, add or update any record, and click **Simulate Rollback Attack**. The SHA-256 checksum verification catches and blocks the older snapshot.