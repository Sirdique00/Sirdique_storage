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

// Check Project Limit per Email (Max 2 projects) & Unique Name Validation
app.post('/api/projects/validate-limit', (req, res) => {
    const { email, projectName } = req.body;
    
    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row && row.count >= 2) {
            return res.status(400).json({ error: 'An riga an kirkiri project biyu (2) da wannan email din. Ba za a iya wuce haka ba.' });
        }

        db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
            if (existing) {
                return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan a wani project din. Da fatan a zabi wani.' });
            }
            res.json({ success: true });
        });
    });
});

// Create Project Finally
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    
    const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    db.run(`INSERT INTO projects (owner_email, name, project_id, api_key) VALUES (?, ?, ?, ?)`,
        [email, projectName, project_id, api_key], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, project_id, api_key, name: projectName });
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
                return res.status(400).json({ error: 'Storage Limit Exceeded! Kowanne project yana da limit na 800MB.' });
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

app.put('/api/data/:id', verifyApiKey, (req, res) => {
    const { title, content } = req.body;
    const { id } = req.params;
    db.run(`UPDATE data_entries SET title = ?, content = ? WHERE id = ? AND project_id = ?`,
        [title, content, id, req.project.project_id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, updated: this.changes });
        });
});

app.delete('/api/data/:id', verifyApiKey, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM data_entries WHERE id = ? AND project_id = ?`, [id, req.project.project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

// --- EXTERNAL WEBSITE AUTH & BRUTE FORCE PROTECTION ---
app.post('/api/auth/signup', verifyApiKey, (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM app_users WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err, user) => {
        if (user) return res.status(400).json({ error: 'Email already registered for this project' });

        db.run(`INSERT INTO app_users (project_id, email, password, is_verified) VALUES (?, ?, ?, 0)`,
            [req.project.project_id, email, password], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, message: 'User registered. Please verify OTP.' });
            });
    });
});

app.post('/api/auth/verify-user', verifyApiKey, (req, res) => {
    const { email } = req.body;
    db.run(`UPDATE app_users SET is_verified = 1 WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'Account verified successfully 100%!' });
    });
});

app.post('/api/auth/login', verifyApiKey, (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM app_users WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email not found' });

        const now = new Date();
        if (user.lock_until && new Date(user.lock_until) > now) {
            const minutesLeft = Math.ceil((new Date(user.lock_until) - now) / 60000);
            return res.status(403).json({ error: `Account locked due to multiple failed password attempts. Try again in ${minutesLeft} minutes.` });
        }

        if (user.password !== password) {
            let attempts = user.failed_attempts + 1;
            let lockTime = null;

            if (attempts >= 9) {
                lockTime = new Date(now.getTime() + 24 * 3600000).toISOString(); // 24 hours
            } else if (attempts >= 6 || attempts >= 3) {
                lockTime = new Date(now.getTime() + 5 * 60000).toISOString(); // 5 mins
            }

            db.run(`UPDATE app_users SET failed_attempts = ?, lock_until = ? WHERE id = ?`, [attempts, lockTime, user.id]);
            return res.status(400).json({ error: `Incorrect password. Attempt ${attempts}/9. (3 kuskure suna kulle account na minti 5, sannan awa 24)` });
        }

        if (user.is_verified === 0) {
            return res.status(401).json({ error: 'Please verify your email first' });
        }

        db.run(`UPDATE app_users SET failed_attempts = 0, lock_until = NULL WHERE id = ?`, [user.id]);
        res.json({ success: true, message: 'Login successful', email: user.email });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
