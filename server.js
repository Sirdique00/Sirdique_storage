const express = require('express');
const sqlite3 = sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname)));

if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

const db = new sqlite3.Database('./sirdique.db', (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS hub_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        reset_code TEXT
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
        file_url TEXT,
        file_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const upload = multer({ storage: multer.memoryStorage() });

// Hub User Authentication & Forgot Password
app.post('/api/hub/signup', (req, res) => {
    const { email, password } = req.body;
    db.run(`INSERT INTO hub_users (email, password) VALUES (?, ?)`, [email, password], function(err) {
        if (err) return res.status(400).json({ error: 'An riga an yi amfani da wannan email din.' });
        res.json({ success: true });
    });
});

app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ? AND password = ?`, [email, password], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email ko password ba daidai ba ne.' });
        res.json({ success: true, email: user.email });
    });
});

// Forgot Password - Generate & Save Reset Code
app.post('/api/hub/forgot-password', (req, res) => {
    const { email } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Wannan email din babu shi a tsarin mu.' });
        
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        db.run(`UPDATE hub_users SET reset_code = ? WHERE email = ?`, [resetCode, email], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, resetCode, message: 'An tura code din sake saita password zuwa email dinka!' });
        });
    });
});

// Reset Password - Save New Password
app.post('/api/hub/reset-password', (req, res) => {
    const { email, code, newPassword } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ? AND reset_code = ?`, [email, code], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Lambar code din da ka saka ba daidai ba ce.' });

        db.run(`UPDATE hub_users SET password = ?, reset_code = NULL WHERE email = ?`, [newPassword, email], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'An canza password din ka da nasara! Yanzu zaka iya yin login.' });
        });
    });
});

// Project Management (Max 2 projects)
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row && row.count >= 2) {
            return res.status(400).json({ error: 'Kuna da iyakan project biyu (2) kacal.' });
        }
        db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
            if (existing) return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan.' });

            const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
            const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

            db.run(`INSERT INTO projects (owner_email, name, project_id, api_key) VALUES (?, ?, ?, ?)`,
                [email, projectName, project_id, api_key], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, name: projectName, project_id, api_key });
                });
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

app.put('/api/projects/update', (req, res) => {
    const { project_id, newName } = req.body;
    db.run(`UPDATE projects SET name = ? WHERE project_id = ?`, [newName, project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Middleware for API Key verification
const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    if (!apiKey) return res.status(401).json({ error: 'API Key is missing' });

    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (err || !project) return res.status(403).json({ error: 'Invalid API Key' });
        req.project = project;
        next();
    });
};

// Supabase-like Tables & Rows API
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

// Bucket Storage API
app.post('/api/bucket/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Babu fayil da aka saka.' });
        const fileSize = req.file.buffer.length;

        if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
            return res.status(400).json({ error: 'Storage Limit Exceeded (800MB limit).' });
        }

        const filename = `img-${Date.now()}.webp`;
        const filepath = path.join(__dirname, 'uploads', filename);

        await sharp(req.file.buffer)
            .resize({ width: 1000, withoutEnlargement: true })
            .webp({ quality: 80 })
            .toFile(filepath);

        const file_url = `/uploads/${filename}`;
        db.run(`INSERT INTO bucket_files (project_id, file_url, file_name) VALUES (?, ?, ?)`,
            [req.project.project_id, file_url, req.file.originalname], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                res.json({ success: true, file_url });
            });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/bucket/files', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM bucket_files WHERE project_id = ? ORDER BY id DESC`, [req.project.project_id], (err, files) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, files });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
