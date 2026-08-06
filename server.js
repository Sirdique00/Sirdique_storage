const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname)));

const dbPath = process.env.RENDER ? path.join('/opt/render/project/src', 'sirdique.db') : './sirdique.db';
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to Sirdique Cloud SQLite database at:', dbPath);
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS hub_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        failed_attempts INTEGER DEFAULT 0,
        ban_until INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        type TEXT,
        expires_at INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_email TEXT,
        name TEXT UNIQUE,
        project_id TEXT UNIQUE,
        api_key TEXT UNIQUE,
        used_storage INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_tables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        table_name TEXT,
        columns TEXT,
        rls_enabled INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        table_name TEXT,
        row_data TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_buckets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        bucket_name TEXT,
        status TEXT DEFAULT 'enabled'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS bucket_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        bucket_name TEXT,
        file_url TEXT,
        file_name TEXT,
        file_size INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const upload = multer({ storage: multer.memoryStorage() });

// 1. SEND VERIFICATION / FORGOT CODE
app.post('/api/hub/send-code', (req, res) => {
    const { email, type } = req.body;
    if(!email) return res.status(400).json({ error: 'Sanya email din ka.' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires_at = Date.now() + 2 * 60 * 1000; // Minti 2

    db.run(`DELETE FROM verification_codes WHERE email = ? AND type = ?`, [email, type], () => {
        db.run(`INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)`, 
            [email, code, type, expires_at], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, code });
            });
    });
});

// 2. VERIFY & REGISTER
app.post('/api/hub/verify-and-register', (req, res) => {
    const { email, password, code } = req.body;
    db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = 'signup' ORDER BY id DESC LIMIT 1`, [email], (err, record) => {
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa (Expired).' });
        if (record.code !== code) return res.status(400).json({ error: 'Code din bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]); // Single-use

        db.run(`INSERT INTO hub_users (email, password, verified) VALUES (?, ?, 1)`, [email, password], function(err) {
            if (err) return res.status(400).json({ error: 'An riga an yi amfani da wannan email din.' });
            res.json({ success: true });
        });
    });
});

// 3. VERIFY & RESET PASSWORD
app.post('/api/hub/verify-and-reset', (req, res) => {
    const { email, newPassword, code } = req.body;
    db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = 'forgot' ORDER BY id DESC LIMIT 1`, [email], (err, record) => {
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Code din ya wuce lokacinsa (Expired).' });
        if (record.code !== code) return res.status(400).json({ error: 'Code din bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]); // Single-use

        db.run(`UPDATE hub_users SET password = ? WHERE email = ?`, [newPassword, email], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'An sauya password din da nasara!' });
        });
    });
});

// 4. LOGIN WITH 3-ATTEMPT BAN PROTECTION (30 mins)
app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email ko password ba daidai ba ne.' });

        if (user.ban_until && Date.now() < user.ban_until) {
            const minutesLeft = Math.ceil((user.ban_until - Date.now()) / 60000);
            return res.status(400).json({ error: `An yi ban na wucin gadi saboda kuskure sau 3. Sake gwadawa bayan minti ${minutesLeft}.` });
        }

        if (user.password !== password) {
            const newAttempts = (user.failed_attempts || 0) + 1;
            if (newAttempts >= 3) {
                const banUntil = Date.now() + 30 * 60 * 1000; // Ban na minti 30
                db.run(`UPDATE hub_users SET failed_attempts = ?, ban_until = ? WHERE email = ?`, [newAttempts, banUntil, email]);
                return res.status(400).json({ error: 'Kayi kuskure sau 3! An yi ban ga account din na tsawon minti 30.' });
            } else {
                db.run(`UPDATE hub_users SET failed_attempts = ? WHERE email = ?`, [newAttempts, email]);
                return res.status(400).json({ error: `Password ba daidai ba ne. Saurara ƙoƙari ${3 - newAttempts} su ka rage.` });
            }
        }

        // Idan yayi daidai, mu share failed attempts
        db.run(`UPDATE hub_users SET failed_attempts = 0, ban_until = 0 WHERE email = ?`, [email]);
        res.json({ success: true, email: user.email });
    });
});

// Project Management
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    if(!projectName) return res.status(400).json({ error: 'Sanya sunan project.' });

    db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan project din.' });

        const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
        const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

        db.run(`INSERT INTO projects (owner_email, name, project_id, api_key) VALUES (?, ?, ?, ?)`,
            [email, projectName, project_id, api_key], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, name: projectName, project_id, api_key });
            });
    });
});

app.post('/api/projects/list', (req, res) => {
    const { email } = req.body;
    db.all(`SELECT * FROM projects WHERE owner_email = ?`, [email], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, projects: rows });
    });
});

const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    if (!apiKey) return res.status(401).json({ error: 'API Key is missing.' });

    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (err || !project) return res.status(403).json({ error: 'Invalid API Key.' });
        req.project = project;
        next();
    });
};

// Tables & Rows API (with RLS support)
app.post('/api/database/tables', verifyApiKey, (req, res) => {
    const { tableName, columns, rlsEnabled } = req.body;
    db.run(`INSERT INTO project_tables (project_id, table_name, columns, rls_enabled) VALUES (?, ?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(columns), rlsEnabled ? 1 : 0], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

app.get('/api/database/tables', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM project_tables WHERE project_id = ?`, [req.project.project_id], (err, tables) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, tables });
    });
});

app.post('/api/database/rows', verifyApiKey, (req, res) => {
    const { tableName, rowData } = req.body;
    db.run(`INSERT INTO project_rows (project_id, table_name, row_data) VALUES (?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(rowData)], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

app.get('/api/database/rows/:tableName', verifyApiKey, (req, res) => {
    const { tableName } = req.params;
    db.all(`SELECT * FROM project_rows WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, rows });
    });
});

// Bucket Management API
app.post('/api/buckets/create', verifyApiKey, (req, res) => {
    const { bucketName } = req.body;
    if(!bucketName) return res.status(400).json({ error: 'Sanya sunan bucket.' });

    db.run(`INSERT INTO project_buckets (project_id, bucket_name, status) VALUES (?, ?, 'enabled')`,
        [req.project.project_id, bucketName], function(err) {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

app.get('/api/buckets/list', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM project_buckets WHERE project_id = ?`, [req.project.project_id], (err, buckets) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ success: true, buckets });
    });
});

app.post('/api/buckets/toggle', verifyApiKey, (req, res) => {
    const { bucketId, status } = req.body;
    db.run(`UPDATE project_buckets SET status = ? WHERE id = ? AND project_id = ?`, [status, bucketId, req.project.project_id], (err) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Bucket File Upload (Auto WebP Compression)
app.post('/api/bucket/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Babu fayil da aka saka.' });
        const { bucketName } = req.body;
        
        // Bincika ko bucket din yana aiki (enabled)
        db.get(`SELECT * FROM project_buckets WHERE project_id = ? AND bucket_name = ?`, [req.project.project_id, bucketName], async (err, bucket) => {
            if(!bucket || bucket.status !== 'enabled') {
                return res.status(400).json({ error: 'Wannan bucket din ba zai karbi fayil ba (ko dai a kashe shi ko babu shi).' });
            }

            const fileSize = req.file.buffer.length;
            if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
                return res.status(400).json({ error: 'Storage Limit Exceeded (800MB).' });
            }

            const filename = `img-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
            const filepath = path.join(uploadsDir, filename);

            await sharp(req.file.buffer)
                .resize({ width: 1000, withoutEnlargement: true })
                .webp({ quality: 80 })
                .toFile(filepath);

            const file_url = `/uploads/${filename}`;
            db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
                [req.project.project_id, bucketName, file_url, req.file.originalname, fileSize], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                    res.json({ success: true, file_url, message: 'An loda hoton kuma an matse shi!' });
                });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/bucket/files/:bucketName', verifyApiKey, (req, res) => {
    const { bucketName } = req.params;
    db.all(`SELECT * FROM bucket_files WHERE project_id = ? AND bucket_name = ? ORDER BY id DESC`, [req.project.project_id, bucketName], (err, files) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, files });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Cloud Storage Server running on port ${PORT}`));
