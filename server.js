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

const db = new sqlite3.Database('./sirdique.db', (err) => {
    if (err) console.error('Error opening database', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        is_verified INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        name TEXT UNIQUE,
        project_id TEXT UNIQUE,
        api_key TEXT UNIQUE,
        storage_used INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS data_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        title TEXT,
        content TEXT,
        file_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        code TEXT,
        expires_at DATETIME
    )`);
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'abubakarsadeeq8533@gmail.com',
        pass: 'ka_sanya_app_password_naka'
    }
});

const upload = multer({ storage: multer.memoryStorage() });

// --- AUTH & ACCOUNT ROUTES ---

// Register & Send OTP (Expires in 1 minute)
app.post('/api/auth/register', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM accounts WHERE email = ?`, [email], (err, acc) => {
        if (acc && acc.is_verified) return res.status(400).json({ error: 'Email already registered!' });

        const saveToDb = () => {
            db.run(`INSERT OR REPLACE INTO accounts (email, password, is_verified) VALUES (?, ?, 0)`, [email, password], () => {
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const expiresAt = new Date(Date.now() + 1 * 60000).toISOString(); // 1 minute

                db.run(`INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)`, [email, otp, expiresAt], () => {
                    transporter.sendMail({
                        from: '"Sirdique Auth" <abubakarsadeeq8533@gmail.com>',
                        to: email,
                        subject: 'Your Sirdique Verification Code',
                        html: `<div style="font-family: Arial; padding: 20px; background: #0f172a; color: #fff; border-radius: 10px;">
                            <h2 style="color: #6366f1;">Sirdique Verification</h2>
                            <p>Your confirmation code is:</p>
                            <h1 style="color: #22c55e; letter-spacing: 5px;">${otp}</h1>
                            <p style="font-size: 12px; color: #94a3b8;">This code expires in 1 minute and becomes useless after use.</p>
                            <hr style="border-color: #334155;">
                            <p style="font-size: 10px; color: #64748b;">Powered by Sirdique Storage</p>
                        </div>`
                    }).catch(console.error);

                    res.json({ success: true, message: 'OTP sent to email (Expires in 1 min)' });
                });
            });
        };
        saveToDb();
    });
});

// Verify OTP & Complete Signup
app.post('/api/auth/verify', (req, res) => {
    const { email, code } = req.body;
    db.get(`SELECT * FROM otps WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1`, [email, code], (err, otpRow) => {
        if (!otpRow || new Date() > new Date(otpRow.expires_at)) {
            return res.status(400).json({ error: 'Invalid or expired OTP (Expires in 1 min)' });
        }

        db.run(`UPDATE accounts SET is_verified = 1 WHERE email = ?`, [email], () => {
            db.run(`DELETE FROM otps WHERE email = ?`, [email]);
            res.json({ success: true, message: 'Account verified successfully!' });
        });
    });
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM accounts WHERE email = ? AND password = ? AND is_verified = 1`, [email, password], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Invalid email, password, or unverified account' });
        res.json({ success: true, email: user.email });
    });
});

// --- PROJECT MANAGEMENT (Max 2 projects per email, Unique names) ---
app.post('/api/projects/create', (req, res) => {
    const { email, name } = req.body;
    
    db.get(`SELECT COUNT(*) as count FROM projects WHERE email = ?`, [email], (err, row) => {
        if (row.count >= 2) {
            return res.status(400).json({ error: 'Kuna da iyaka! Zaku iya kirkirar project biyu (2) kacal da email ɗaya.' });
        }

        db.get(`SELECT * FROM projects WHERE name = ?`, [name], (err, existingName) => {
            if (existingName) {
                return res.status(400).json({ error: 'Wannan sunan project yana da shi, ka zabi wani sunan!' });
            }

            const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
            const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

            db.run(`INSERT INTO projects (email, name, project_id, api_key) VALUES (?, ?, ?, ?)`, 
                [email, name, project_id, api_key], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, project_id, api_key, name });
                });
        });
    });
});

app.get('/api/projects/list/:email', (req, res) => {
    db.all(`SELECT * FROM projects WHERE email = ?`, [req.params.email], (err, rows) => {
        res.json({ success: true, projects: rows });
    });
});

// --- API STORAGE (800MB limit per project, compression) ---
const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (!project) return res.status(403).json({ error: 'Invalid API Key' });
        req.project = project;
        next();
    });
};

app.post('/api/save', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        if (req.project.storage_used >= 800 * 1024 * 1024) {
            return res.status(400).json({ error: 'Project Storage Limit reached (800MB max)' });
        }

        let file_url = null;
        let fileSize = 0;

        if (req.file) {
            fileSize = req.file.size;
            const filename = `img-${Date.now()}.webp`;
            const filepath = path.join(__dirname, 'uploads', filename);
            
            await sharp(req.file.buffer)
                .resize({ width: 1000, withoutEnlargement: true })
                .webp({ quality: 80 })
                .toFile(filepath);

            file_url = `/uploads/${filename}`;
        }

        db.run(`INSERT INTO data_entries (project_id, title, content, file_url) VALUES (?, ?, ?, ?)`,
            [req.project.project_id, req.body.title, req.body.content, file_url], () => {
                db.run(`UPDATE projects SET storage_used = storage_used + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                res.json({ success: true, file_url });
            });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/data', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM data_entries WHERE project_id = ?`, [req.project.project_id], (err, rows) => {
        res.json({ success: true, data: rows, storage_limit_mb: 800, storage_used_bytes: req.project.storage_used });
    });
});

// System Total Storage Info Route
app.get('/api/system/storage-info', (req, res) => {
    db.get(`SELECT SUM(storage_used) as total FROM projects`, (err, row) => {
        res.json({ success: true, total_storage_used_mb: (row.total || 0) / (1024 * 1024), server_total_capacity_gb: 10 });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage running on port ${PORT}`));
