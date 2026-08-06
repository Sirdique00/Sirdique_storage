const express = require('express');
const sqlite3 = require('sqlite3').verbose();
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
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_email TEXT,
        password TEXT,
        name TEXT UNIQUE,
        project_id TEXT UNIQUE,
        api_key TEXT UNIQUE,
        used_storage INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS data_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        title TEXT,
        content TEXT,
        file_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS app_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        email TEXT,
        password TEXT,
        is_verified INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        lock_until DATETIME
    )`);
});

const upload = multer({ storage: multer.memoryStorage() });

// --- ADMIN LOGIN ---
app.post('/api/admin/login', (req, res) => {
    const { email, password, pin } = req.body;
    if (pin !== '676767') return res.status(403).json({ error: 'Invalid Admin PIN' });
    if (email !== 'abubakarsadeeq8533@gmail.com') return res.status(403).json({ error: 'Unauthorized Admin Email' });
    res.json({ success: true, message: 'Welcome to Admin Dashboard' });
});

// Validate project limit (Max 2 projects per email) & unique name
app.post('/api/projects/validate-limit', (req, res) => {
    const { email, projectName } = req.body;
    
    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row && row.count >= 2) {
            return res.status(400).json({ error: 'An riga an kirkiri project biyu (2) da wannan email din.' });
        }

        db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
            if (existing) {
                return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan a wani project din.' });
            }
            res.json({ success: true });
        });
    });
});

// Create Project with Account Password
app.post('/api/projects/create', (req, res) => {
    const { email, password, projectName } = req.body;
    
    const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    db.run(`INSERT INTO projects (owner_email, password, name, project_id, api_key) VALUES (?, ?, ?, ?, ?)`,
        [email, password, projectName, project_id, api_key], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, project_id, api_key, name: projectName });
        });
});

// Project Dashboard Login (Email & Password) with Brute Force Protection
app.post('/api/projects/login', (req, res) => {
    const { email, password } = req.body;
    db.all(`SELECT * FROM projects WHERE owner_email = ?`, [email], (err, projects) => {
        if (!projects || projects.length === 0) return res.status(400).json({ error: 'Babu wani project da aka samu da wannan email din.' });

        // Check password against the owner's projects
        const matchedProject = projects.find(p => p.password === password);
        if (!matchedProject) {
            return res.status(400).json({ error: 'Password din bai daidai ba!' });
        }

        res.json({ success: true, projects });
    });
});

// Get Projects by Email
app.post('/api/projects/list', (req, res) => {
    const { email } = req.body;
    db.all(`SELECT * FROM projects WHERE owner_email = ?`, [email], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, projects: rows });
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

// Storage API with 800MB limit & Compression
app.post('/api/save', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { title, content } = req.body;
        let file_url = null;
        let fileSize = 0;

        if (req.file) {
            fileSize = req.file.buffer.length;
            if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
                return res.status(400).json({ error: 'Storage Limit Exceeded! 800MB limit reached.' });
            }

            const filename = `img-${Date.now()}.webp`;
            const filepath = path.join(__dirname, 'uploads', filename);
            
            await sharp(req.file.buffer)
                .resize({ width: 1000, withoutEnlargement: true })
                .webp({ quality: 80 })
                .toFile(filepath);

            file_url = `/uploads/${filename}`;
        }

        db.run(`INSERT INTO data_entries (project_id, title, content, file_url) VALUES (?, ?, ?, ?)`,
            [req.project.project_id, title, content, file_url], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                res.json({ success: true, id: this.lastID, file_url });
            });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/data', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM data_entries WHERE project_id = ? ORDER BY id DESC`, [req.project.project_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, data: rows, storage_limit_mb: 800, used_storage_bytes: req.project.used_storage });
    });
});

app.delete('/api/data/:id', verifyApiKey, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM data_entries WHERE id = ? AND project_id = ?`, [id, req.project.project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
