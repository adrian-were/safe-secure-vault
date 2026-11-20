# SafeSecure — Zero-Knowledge Password Manager

**SafeSecure** is a full-stack, zero-knowledge password manager built for **ICS 3201 (Cryptography)**. It combines a modern, privacy-focused web interface with a Node.js and PostgreSQL backend, ensuring that plaintext domains, passwords, and master keys are never stored on disk or in the database.

---

## Cryptographic Architecture

All cryptographic operations use the standard Web Crypto (`SubtleCrypto`) API without custom primitives:

* **Key Derivation (`PBKDF2`):** Derives a master key from the user's master password and a random 128-bit salt using 100,000 iterations of PBKDF2-SHA256 to resist brute-force attacks.
* **Key Splitting & Domain Obfuscation (`HMAC-SHA256`):** Uses HMAC as a Pseudorandom Function (PRF) to split the master key into independent sub-keys—one for hashing website/domain names (allowing $O(1)$ lookups with zero plaintext domain leakage) and one for encryption.
* **Authenticated Encryption & Swap Defense (`AES-GCM`):** Encrypts each password individually with a fresh 96-bit IV. The domain's HMAC tag is bound to the ciphertext via AES-GCM's `additionalData` (AAD), immediately detecting and rejecting **swap attacks**.
* **Length Hiding (Fixed Padding):** Pads all secrets to a uniform 64-byte payload before encryption so an attacker inspecting the database cannot distinguish a 4-character PIN from a 32-character password.
* **Rollback Protection (`SHA-256`):** Computes a SHA-256 checksum of the serialized vault (`dump()`). Reloading the vault (`load()`) verifies this hash to detect tampering or database rollback attacks.

---

## Application Features

* **Modern Privacy UI:** Clean Indigo & Charcoal theme with a persistent **Light / Dark mode** toggle.
* **Built-in Password Generator:** Cryptographically secure random password generator (`crypto.getRandomValues`) with customizable length (8–32 chars), character sets, real-time strength meter, and color-coded character syntax (blue for numbers, pink for symbols) to distinguish ambiguous characters like `0`/`O` and `1`/`l`.
* **Visibility Controls:** Show/hide toggles on all password inputs and decrypted results, plus one-click clipboard copy with toast notifications.
* **Live Backend Storage Inspector:** Built-in UI panel to view the raw encrypted JSON and SHA-256 checksum currently stored in PostgreSQL.

---

## Project Structure

```text
secure-vault-project/
├── lib.js                  # Cryptographic helper utilities (encoding, buffers, randomness)
├── secure-vault.js         # Core SecureVault class (init, load, dump, set, get, remove)
├── server.js               # Node.js HTTP API server & PostgreSQL integration
├── index.html              # Responsive SafeSecure frontend UI
├── safesecure_backup.sql   # (Optional) Exported PostgreSQL database snapshot
├── package.json            # Project metadata & pg dependency
└── README.md               # Project documentation
```

---

## Prerequisites

* **Node.js** (v18+ recommended, with built-in Web Crypto support)
* **PostgreSQL** (local installation on Ubuntu/WSL, macOS, or Windows)

---

## Setup & Installation

### 1. Clone the Repository & Install Dependencies

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd <YOUR_REPO_FOLDER>
npm install
```

### 2. Configure PostgreSQL

Start the PostgreSQL service and configure the database credentials to match `server.js`:

```bash
sudo service postgresql start
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'safesecure123';"
sudo -u postgres psql -c "CREATE DATABASE safesecure;"
```

Next, choose **one** of the following options:

* **Option A — Import the shared database backup (recommended for group demos):**
  ```bash
  sudo -u postgres psql -d safesecure < safesecure_backup.sql
  ```

* **Option B — Create a fresh, empty table:**
  ```bash
  sudo -u postgres psql -d safesecure -c "
  CREATE TABLE IF NOT EXISTS vault_storage (
      id INT PRIMARY KEY DEFAULT 1,
      vault_json TEXT NOT NULL,
      trusted_hash TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );"
  ```

*(You can also override the database connection string by setting the `DATABASE_URL` environment variable.)*

---

## Running the Application

1. Start the Node.js backend server:
   ```bash
   node server.js
   ```
2. Open your browser and navigate to:
   ```text
   http://localhost:3001
   ```
   > **Note:** Always access the app via `http://localhost:3001` rather than opening `index.html` directly so the frontend can communicate with the backend API.

3. Enter a **Master Password** to initialize a new vault (or enter the shared master password if you imported `safesecure_backup.sql`).

---

## Inspecting & Managing the PostgreSQL Backend

### View Encrypted Records in Terminal
To demonstrate that PostgreSQL only stores the salt, HMAC-hashed domain keys, AES-GCM ciphertexts, and SHA-256 checksum:

```bash
sudo -u postgres psql -d safesecure -x -c "SELECT id, updated_at, trusted_hash, vault_json FROM vault_storage;"
```

### Reset the Vault
Because the master password is never stored anywhere, it cannot be recovered if forgotten. To wipe the database and start fresh with a new master password:

```bash
sudo -u postgres psql -d safesecure -c "TRUNCATE TABLE vault_storage;"
```

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the SafeSecure web interface (`index.html`). |
| `GET` | `/api/status` | Checks if the vault is unlocked and whether a vault exists in PostgreSQL. |
| `POST` | `/api/unlock` | Initializes a new vault or unlocks the existing vault using the master password. |
| `POST` | `/api/lock` | Clears active cryptographic keys from server memory. |
| `POST` | `/api/set` | Encrypts and stores (or updates) a password for a given domain. |
| `POST` | `/api/get` | Looks up, authenticates, and decrypts the password for a given domain. |
| `POST` | `/api/remove` | Deletes an entry from the vault and updates PostgreSQL. |
| `GET` | `/api/raw-db` | Returns the raw encrypted `vault_json` and `trusted_hash` from PostgreSQL. |