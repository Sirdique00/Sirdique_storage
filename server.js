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
        verified INTEGER DEFAULT 1,
        failed_attempts INTEGER DEFAULT 0,
        banned_until INTEGER DEFAULT 0
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
        used_storage INTEGER DEFAULT 0,
        rls_enabled INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_buckets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        bucket_name TEXT,
        is_enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_tables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        table_name TEXT,
        columns TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS project_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        table_name TEXT,
        row_data TEXT
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

// 1. SEND OTP CODE (Signup / Forgot)
app.post('/api/hub/send-code', (req, res) => {
    const { email, type } = req.body;
    if(!email) return res.status(400).json({ error: 'Sanya email din ka.' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires_at = Date.now() + 2 * 60 * 1000; // Minti biyu (120 seconds)

    db.run(`DELETE FROM verification_codes WHERE email = ? AND type = ?`, [email, type], (err) => {
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
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura zuwa wannan email din.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa (Expired).' });
        if (record.code !== code) return res.status(400).json({ error: 'Wannan code din bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]);

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
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa (Expired).' });
        if (record.code !== code) return res.status(400).json({ error: 'Code din da aka saka bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]);

        db.run(`UPDATE hub_users SET password = ?, failed_attempts = 0, banned_until = 0 WHERE email = ?`, [newPassword, email], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'An sauya password din da nasara!' });
        });
    });
});

// 4. LOGIN WITH 3 ATTEMPTS LOCKOUT (30 MINTI BAN)
app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email ko password ba daidai ba ne.' });

        if (user.banned_until && user.banned_until > Date.now()) {
            const mins = Math.ceil((user.banned_until - Date.now()) / 60000);
            return res.status(403).json({ error: `Account dinka yana karkashin kariya. An kulle shi saboda kuskuren password sau uku. Jira na tsawon minti ${mins}.` });
        }

        if (user.password !== password) {
            const failed = (user.failed_attempts || 0) + 1;
            if (failed >= 3) {
                const banTime = Date.now() + 30 * 60 * 1000; // 30 Minti
                db.run(`UPDATE hub_users SET failed_attempts = ?, banned_until = ? WHERE email = ?`, [failed, banTime, email]);
                return res.status(403).json({ error: 'Kayi kuskuren password sau uku! An kulle account din na tsawon minti 30.' });
            } else {
                db.run(`UPDATE hub_users SET failed_attempts = ? WHERE email = ?`, [failed, email]);
                return res.status(400).json({ error: `Password ba daidai ba ne. Saurara kokari ${3 - failed} kafin a kulle account din.` });
            }
        } else {
            db.run(`UPDATE hub_users SET failed_attempts = 0, banned_until = 0 WHERE email = ?`, [email]);
            res.json({ success: true, email: user.email });
        }
    });
});

// PROJECT MANAGEMENT
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
                // Create a default bucket
                db.run(`INSERT INTO project_buckets (project_id, bucket_name) VALUES (?, ?)`, [project_id, 'default-bucket']);
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

app.post('/api/projects/toggle-rls', (req, res) => {
    const { project_id, rls_enabled } = req.body;
    db.run(`UPDATE projects SET rls_enabled = ? WHERE project_id = ?`, [rls_enabled, project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
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

// BUCKETS MANAGEMENT API
app.post('/api/buckets/create', verifyApiKey, (req, res) => {
    const { bucketName } = req.body;
    if(!bucketName) return res.status(400).json({ error: 'Sanya sunan bucket.' });

    db.get(`SELECT * FROM project_buckets WHERE project_id = ? AND bucket_name = ?`, [req.project.project_id, bucketName], (err, existing) => {
        if(existing) return res.status(400).json({ error: 'Wannan bucket din yana da shi riga.' });

        db.run(`INSERT INTO project_buckets (project_id, bucket_name) VALUES (?, ?)`, [req.project.project_id, bucketName], function(err) {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

app.get('/api/buckets/list', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM project_buckets WHERE project_id = ?`, [req.project.project_id], (err, buckets) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ success: true, buckets });
    });
});

// TABLES & ROWS API
app.post('/api/database/tables', verifyApiKey, (req, res) => {
    const { tableName, columns } = req.body;
    db.run(`INSERT INTO project_tables (project_id, table_name, columns) VALUES (?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
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

// BUCKET UPLOAD API (Optimized Compression)
app.post('/api/bucket/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Babu fayil da aka saka.' });
        const bucketName = req.body.bucketName || 'default-bucket';
        const fileSize = req.file.buffer.length;

        if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
            return res.status(400).json({ error: 'Storage Limit Exceeded (800MB limit).' });
        }

        const filename = `img-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
        const filepath = path.join(uploadsDir, filename);

        await sharp(req.file.buffer)
            .resize({ width: 1200, withoutEnlargement: true })
            .webp({ quality: 85 })
            .toFile(filepath);

        const file_url = `/uploads/${filename}`;
        db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
            [req.project.project_id, bucketName, file_url, req.file.originalname, fileSize], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                res.json({ success: true, file_url, filename });
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

// PUBLIC SDK ENDPOINTS
app.post('/api/v1/data/insert', verifyApiKey, (req, res) => {
    const { tableName, rowData } = req.body;
    if (!tableName || !rowData) return res.status(400).json({ error: 'TableName da rowData ana bukatarsu.' });

    db.get(`SELECT * FROM project_tables WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, table) => {
        if (!table) return res.status(404).json({ error: `Table '${tableName}' bai wanzu ba.` });

        db.run(`INSERT INTO project_rows (project_id, table_name, row_data) VALUES (?, ?, ?)`,
            [req.project.project_id, tableName, JSON.stringify(rowData)], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, message: 'An adana bayanan cikin nasara!' });
            });
    });
});

app.get('/api/v1/data/:tableName', verifyApiKey, (req, res) => {
    const { tableName } = req.params;
    db.all(`SELECT row_data FROM project_rows WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => JSON.parse(r.row_data));
        res.json({ success: true, data: parsedRows });
    });
});

app.post('/api/v1/storage/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Babu fayil din hoto.' });
        const bucketName = req.body.bucketName || 'default-bucket';
        const fileSize = req.file.buffer.length;

        if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
            return res.status(400).json({ error: 'Storage Limit Exceeded (800MB).' });
        }

        const filename = `pub-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
        const filepath = path.join(uploadsDir, filename);

        await sharp(req.file.buffer)
            .resize({ width: 1000, withoutEnlargement: true })
            .webp({ quality: 80 })
            .toFile(filepath);

        const file_url = `${req.protocol}://${req.get('host')}/uploads/${filename}`;
        
        db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
            [req.project.project_id, bucketName, file_url, req.file.originalname, fileSize], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                res.json({ success: true, file_url, message: 'An loda kuma an matse hoton cikin nasara!' });
            });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Cloud Storage Server running on port ${PORT}`));
