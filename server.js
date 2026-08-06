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

if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Database Setup
const db = new sqlite3.Database('./sirdique.db', (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
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

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        email TEXT,
        password TEXT,
        is_verified INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        lock_until DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        expires_at DATETIME
    )`);
});

// Nodemailer setup (Ka sanya email da app password naka na Gmail anan domin tura OTP)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'ka_sanya_email_naka@gmail.com',
        pass: 'ka_sanya_app_password_naka'
    }
});

// Image compression middleware using multer & sharp
const upload = multer({ storage: multer.memoryStorage() });

// --- PROJECT & API ROUTES ---

// 1. Kirkirar Project & API Key
app.post('/api/projects/create', (req, res) => {
    const { name } = req.body;
    const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const api_key = 'SK-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    db.run(`INSERT INTO projects (name, project_id, api_key) VALUES (?, ?, ?)`, [name, project_id, api_key], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, project_id, api_key, name });
    });
});

// Middleware to verify API Key
const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    if (!apiKey) return res.status(401).json({ error: 'API Key is missing' });

    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (err || !project) return res.status(403).json({ error: 'Invalid API Key' });
        req.project = project;
        next();
    });
};

// 2. Ajiye Bayanai (Storage) da Image Compression
app.post('/api/save', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { title, content } = req.body;
        let file_url = null;

        if (req.file) {
            const filename = `img-${Date.now()}.webp`;
            const filepath = path.join(__dirname, 'uploads', filename);
            
            // Matse hoton (compression) ta yadda ba zai yi nauyi ba
            await sharp(req.file.buffer)
                .resize({ width: 1000, withoutEnlargement: true })
                .webp({ quality: 80 })
                .toFile(filepath);

            file_url = `/uploads/${filename}`;
        }

        db.run(`INSERT INTO data_entries (project_id, title, content, file_url) VALUES (?, ?, ?, ?)`,
            [req.project.project_id, title, content, file_url], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, id: this.lastID, file_url });
            });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 3. Karanta Bayanai (GET)
app.get('/api/data', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM data_entries WHERE project_id = ? ORDER BY id DESC`, [req.project.project_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, data: rows });
    });
});

// 4. Update Bayani
app.put('/api/data/:id', verifyApiKey, (req, res) => {
    const { title, content } = req.body;
    const { id } = req.params;
    db.run(`UPDATE data_entries SET title = ?, content = ? WHERE id = ? AND project_id = ?`,
        [title, content, id, req.project.project_id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, updated: this.changes });
        });
});

// 5. Delete Bayani
app.delete('/api/data/:id', verifyApiKey, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM data_entries WHERE id = ? AND project_id = ?`, [id, req.project.project_id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

// --- AUTHENTICATION & SECURITY ROUTES (Sign Up, Login & OTP) ---

// Sign Up
app.post('/api/auth/signup', verifyApiKey, (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err, user) => {
        if (user) return res.status(400).json({ error: 'Email already registered for this project' });

        db.run(`INSERT INTO users (project_id, email, password, is_verified) VALUES (?, ?, ?, 0)`,
            [req.project.project_id, email, password], function(err) {
                if (err) return res.status(500).json({ error: err.message });

                // Generate OTP (Expires in 2 minutes)
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const expiresAt = new Date(Date.now() + 2 * 60000).toISOString();

                db.run(`INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)`, [email, otp, expiresAt], () => {
                    // Tura email (Ka tabbatar ka sa daidaitaccen tsari a sama)
                    transporter.sendMail({
                        from: 'Sirdique Auth <no-reply@sirdique.com>',
                        to: email,
                        subject: 'Confirmation Code',
                        text: `Your confirmation code is: ${otp}. It expires in 2 minutes.`
                    }).catch(console.error);

                    res.json({ success: true, message: 'OTP sent to email' });
                });
            });
    });
});

// Verify OTP
app.post('/api/auth/verify-otp', verifyApiKey, (req, res) => {
    const { email, code } = req.body;
    db.get(`SELECT * FROM otps WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1`, [email, code], (err, otpRow) => {
        if (!otpRow || new Date() > new Date(otpRow.expires_at)) {
            return res.status(400).json({ error: 'Invalid or expired OTP (Expires in 2 mins)' });
        }

        db.run(`UPDATE users SET is_verified = 1 WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Account verified successfully!' });
        });
    });
});

// Login with Brute-force Protection (3 attempts -> 5 mins lock -> 24 hours lock)
app.post('/api/auth/login', verifyApiKey, (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email not found' });

        const now = new Date();
        if (user.lock_until && new Date(user.lock_until) > now) {
            const minutesLeft = Math.ceil((new Date(user.lock_until) - now) / 60000);
            return res.status(403).json({ error: `Account locked due to multiple failed attempts. Try again in ${minutesLeft} minutes.` });
        }

        if (user.password !== password) {
            let attempts = user.failed_attempts + 1;
            let lockTime = null;

            if (attempts >= 9) {
                lockTime = new Date(now.getTime() + 24 * 3600000).toISOString(); // 24 hours
            } else if (attempts >= 6) {
                lockTime = new Date(now.getTime() + 5 * 60000).toISOString(); // 5 mins
            } else if (attempts >= 3) {
                lockTime = new Date(now.getTime() + 5 * 60000).toISOString(); // 5 mins
            }

            db.run(`UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?`, [attempts, lockTime, user.id]);
            return res.status(400).json({ error: `Incorrect password. Attempt ${attempts}/9` });
        }

        if (user.is_verified === 0) {
            return res.status(401).json({ error: 'Please verify your email first' });
        }

        // Reset failed attempts on success
        db.run(`UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?`, [user.id]);
        res.json({ success: true, message: 'Login successful', email: user.email });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
