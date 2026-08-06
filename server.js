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
    db.run(`CREATE TABLE IF NOT EXISTS hub_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_email TEXT,
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
});

const upload = multer({ storage: multer.memoryStorage() });

// Hub User Authentication (Sign Up & Login)
app.post('/api/hub/signup', (req, res) => {
    const { email, password } = req.body;
    db.run(`INSERT INTO hub_users (email, password) VALUES (?, ?)`, [email, password], function(err) {
        if (err) return res.status(400).json({ error: 'An riga an yi amfani da wannan email din ko kuma akwai matsala.' });
        res.json({ success: true, message: 'An yi register da nasara!' });
    });
});

app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ? AND password = ?`, [email, password], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email ko password ba daidai ba ne.' });
        res.json({ success: true, email: user.email });
    });
});

// Project Validation & Creation (Max 2 projects per email, unique name)
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    
    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row && row.count >= 2) {
            return res.status(400).json({ error: 'Kuna da iyakan project biyu (2) kacal da zaku iya kirkira.' });
        }

        db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
            if (existing) {
                return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan a wani project din.' });
            }

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
                return res.status(400).json({ error: 'Storage Limit Exceeded (800MB limit).' });
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
        res.json({ success: true, data: rows });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
