// server.js (PostgreSQL Backend)
const http = require('http');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { SecureVault } = require('./secure-vault');

const PORT = 3001;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:safesecure123@localhost:5432/safesecure'
});

let activeVault = null;

// Save encrypted vault & SHA-256 checksum to PostgreSQL
async function saveToDB() {
    const [repr, sha256Hash] = await activeVault.dump();
    await pool.query(
        `INSERT INTO vault_storage (id, vault_json, trusted_hash, updated_at)
         VALUES (1, $1, $2, NOW())
         ON CONFLICT (id)
         DO UPDATE SET vault_json = EXCLUDED.vault_json,
                       trusted_hash = EXCLUDED.trusted_hash,
                       updated_at = NOW()`,
        [repr, sha256Hash]
    );
    return sha256Hash;
}

// Load encrypted vault from PostgreSQL
async function loadFromDB() {
    const res = await pool.query('SELECT vault_json, trusted_hash FROM vault_storage WHERE id = 1');
    return res.rows[0] || null;
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => (data += chunk));
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch (e) {
                reject(new Error('Invalid JSON body'));
            }
        });
    });
}

function sendJSON(res, status, payload) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
}

const server = http.createServer(async (req, res) => {
    try {
        // Serve Frontend UI
        if (req.method === 'GET' && req.url === '/') {
            const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf-8');
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return res.end(html);
        }

        // Check status
        if (req.method === 'GET' && req.url === '/api/status') {
            const row = await loadFromDB();
            return sendJSON(res, 200, {
                unlocked: Boolean(activeVault),
                existsOnDisk: Boolean(row)
            });
        }

        // Unlock existing vault from Postgres OR initialize a new one
        if (req.method === 'POST' && req.url === '/api/unlock') {
            const { masterPassword } = await readBody(req);
            if (!masterPassword) return sendJSON(res, 400, { error: 'Master password is required.' });

            const row = await loadFromDB();
            if (row) {
                activeVault = await SecureVault.load(masterPassword, row.vault_json, row.trusted_hash);
                return sendJSON(res, 200, { message: 'Vault unlocked from PostgreSQL.' });
            } else {
                activeVault = await SecureVault.init(masterPassword);
                await saveToDB();
                return sendJSON(res, 200, { message: 'New vault created and saved to PostgreSQL.' });
            }
        }

        // Lock vault
        if (req.method === 'POST' && req.url === '/api/lock') {
            activeVault = null;
            return sendJSON(res, 200, { message: 'Vault locked.' });
        }

        // View raw encrypted JSON stored in PostgreSQL
        if (req.method === 'GET' && req.url === '/api/raw-db') {
            const row = await loadFromDB();
            if (!row) return sendJSON(res, 404, { error: 'No vault found in PostgreSQL yet.' });
            const prettyJson = JSON.stringify(JSON.parse(row.vault_json), null, 2);
            return sendJSON(res, 200, { rawJson: prettyJson, sha256: row.trusted_hash });
        }

        if (!activeVault) {
            return sendJSON(res, 401, { error: 'Vault is locked. Please unlock first.' });
        }

        // Add or update password
        if (req.method === 'POST' && req.url === '/api/set') {
            const { domain, password } = await readBody(req);
            if (!domain || !password) return sendJSON(res, 400, { error: 'Domain and password are required.' });
            await activeVault.set(domain.trim(), password);
            await saveToDB();
            return sendJSON(res, 200, { message: `Saved encrypted password for ${domain} to PostgreSQL.` });
        }

        // Retrieve password
        if (req.method === 'POST' && req.url === '/api/get') {
            const { domain } = await readBody(req);
            if (!domain) return sendJSON(res, 400, { error: 'Domain is required.' });
            const password = await activeVault.get(domain.trim());
            if (password === null) return sendJSON(res, 404, { error: `No password stored for "${domain}".` });
            return sendJSON(res, 200, { domain, password });
        }

        // Delete password
        if (req.method === 'POST' && req.url === '/api/remove') {
            const { domain } = await readBody(req);
            if (!domain) return sendJSON(res, 400, { error: 'Domain is required.' });
            const removed = await activeVault.remove(domain.trim());
            if (!removed) return sendJSON(res, 404, { error: `No password found for "${domain}".` });
            await saveToDB();
            return sendJSON(res, 200, { message: `Deleted entry for ${domain} from PostgreSQL.` });
        }

        sendJSON(res, 404, { error: 'Route not found.' });
    } catch (err) {
        sendJSON(res, 500, { error: err.message });
    }
});

server.listen(PORT, () => {
    console.log(`\n=======================================================`);
    console.log(`  SafeSecure + PostgreSQL running at http://localhost:${PORT}`);
    console.log(`=======================================================\n`);
});