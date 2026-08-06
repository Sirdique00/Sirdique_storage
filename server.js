const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const sharp = require('sharp');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname)));

if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const db = new sqlite3.Database('./sirdique.db', (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS dashboard_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        is_verified INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        expires_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_email TEXT,
        name TEXT UNIQUE,
        project_id TEXT UNIQUE,
        api_key TEXT UNIQUE
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

// Nodemailer setup (Ka sanya email da app password naka)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'ka_sanya_email_naka@gmail.com',
        pass: 'ka_sanya_app_password_naka'
    }
});

const upload = multer({ storage: multer.memoryStorage() });

// --- DASHBOARD AUTH & PROJECT ROUTES ---

// 1. Send OTP for Registration (Expires in 1 minute)
app.post('/api/dash/send-otp', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    db.get(`SELECT * FROM dashboard_users WHERE email = ?`, [email], (err, user) => {
        if (user && user.is_verified === 1) {
            return res.status(400).json({ error: 'Email already registered. Please login.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 60000).toISOString(); // Minti 1

        db.run(`INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)`, [email, otp, expiresAt], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            transporter.sendMail({
                from: 'Sirdique Hub <no-reply@sirdique.com>',
                to: email,
                subject: 'Sirdique Verification Code',
                text: `Your code is: ${otp}. It expires in 1 minute and can only be used once.`
            }).catch(console.error);

            res.json({ success: true, message: 'OTP sent to email (Expires in 1 min)' });
        });
    });
});

// 2. Register / Verify OTP & Set Password
app.post('/api/dash/register', (req, res) => {
    const { email, code, password } = req.body;
    db.get(`SELECT * FROM otps WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1`, [email, code], (err, otpRow) => {
        if (!otpRow || new Date() > new Date(otpRow.expires_at)) {
            return res.status(400).json({ error: 'Invalid or expired OTP (Expires in 1 min)' });
        }

        // Delete OTP so it becomes useless
        db.run(`DELETE FROM otps WHERE id = ?`, [otpRow.id]);

        db.run(`INSERT OR REPLACE INTO dashboard_users (email, password, is_verified) VALUES (?, ?, 1)`, [email, password], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Account created successfully!' });
        });
    });
});

// 3. Login
app.post('/api/dash/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM dashboard_users WHERE email = ? AND password = ?`, [email, password], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Invalid email or password' });
        res.json({ success: true, email: user.email });
    });
});

// 4. Get User Projects (Max 2 rule check)
app.get('/api/dash/projects/:email', (req, res) => {
    const { email } = req.params;
    db.all(`SELECT * FROM projects WHERE owner_email = ?`, [email], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, projects: rows });
    });
});

// 5. Create Project (Max 2 per email & Unique Name)
app.post('/api/dash/projects/create', (req, res) => {
    const { email, name } = req.body;
    if (!email || !name) return res.status(400).json({ error: 'Email and project name required' });

    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row.count >= 2) {
            return res.status(400).json({ error: 'Iyakacin project da za ka iya kirkira da wannan email shine biyu (2).' });
        }

        db.get(`SELECT * FROM projects WHERE name = ?`, [name], (err, existingName) => {
            if (existingName) {
                return res.status(400).json({ error: 'Wannan sunan project din an riga an yi amfani da shi. Ka sanya wani.' });
            }

            const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
            const api_key = 'SK-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

            db.run(`INSERT INTO projects (owner_email, name, project_id, api_key) VALUES (?, ?, ?, ?)`,
                [email, name, project_id, api_key], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, project_id, api_key, name });
                });
        });
    });
});

// --- EXTERNAL API STORAGE ROUTES (Godiya ga API Key) ---
const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    if (!apiKey) return res.status(401).json({ error: 'API Key is missing' });

    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (err || !project) return res.status(403).json({ error: 'Invalid API Key' });
        req.project = project;
        next();
    });
};

app.post('/api/save', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { title, content } = req.body;
        let file_url = null;
        if (req.file) {
            const filename = `img-${Date.now()}.webp`;
            const filepath = path.join(__dirname, 'uploads', filename);
            await sharp(req.file.buffer).resize({ width: 1000, withoutEnlargement: true }).webp({ quality: 80 }).toFile(filepath);
            file_url = `/uploads/${filename}`;
        }
        db.run(`INSERT INTO data_entries (project_id, title, content, file_url) VALUES (?, ?, ?, ?)`,
            [req.project.project_id, title, content, file_url], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, id: this.lastID, file_url });
            });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/data', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM data_entries WHERE project_id = ? ORDER BY id DESC`, [req.project.project_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, data: rows });
    });
});

app.put('/api/data/:id', verifyApiKey, (req, res) => {
    const { title, content } = req.body;
    db.run(`UPDATE data_entries SET title = ?, content = ? WHERE id = ? AND project_id = ?`,
        [title, content, req.params.id, req.project.project_id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, updated: this.changes });
        });
});

app.delete('/api/data/:id', verifyApiKey, (req, res) => {
    db.run(`DELETE FROM data_entries WHERE id = ? AND project_id = ?`, [req.params.id, req.project.project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
