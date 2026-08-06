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
    db.run(`CREATE TABLE IF NOT EXISTS admin_users (
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

    db.run(`CREATE TABLE IF NOT EXISTS app_users (
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
        expires_at DATETIME,
        is_used INTEGER DEFAULT 0
    )`);
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'abubakarsadeeq8533@gmail.com',
        pass: 'ka_sanya_gmail_app_password_naka'
    }
});

const upload = multer({ storage: multer.memoryStorage() });

// --- ADMIN & AUTH ROUTES ---

// Admin Registration / Login verification
app.post('/api/admin/login', (req, res) => {
    const { email, password, pin } = req.body;
    if (pin !== '676767') return res.status(403).json({ error: 'Invalid Admin PIN' });
    if (email !== 'abubakarsadeeq8533@gmail.com') return res.status(403).json({ error: 'Unauthorized Admin Email' });
    res.json({ success: true, message: 'Welcome to Admin Dashboard' });
});

// Send OTP for Project Registration (Expires in 1 minute)
app.post('/api/project-auth/send-otp', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    // Check project limit per email (Max 2 projects)
    db.get(`SELECT COUNT(*) as count FROM projects WHERE owner_email = ?`, [email], (err, row) => {
        if (row && row.count >= 2) {
            return res.status(400).json({ error: 'An riga an kirkiri project biyu (2) da wannan email din. Ba za a iya wuce haka ba.' });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 1 * 60000).toISOString(); // 1 minute expiry

        db.run(`INSERT INTO otps (email, code, expires_at, is_used) VALUES (?, ?, ?, 0)`, [email, code, expiresAt], () => {
            transporter.sendMail({
                from: 'Sirdique Storage <abubakarsadeeq8533@gmail.com>',
                to: email,
                subject: 'Sirdique Storage - Project Registration Code',
                text: `Sannu! Lambar tabbatar da account dinka ta Sirdique Storage ita ce: ${code}\n\nWannan lambar za ta mutu bayan minti daya (1 minute).\n\nPowered by Sirdique`
            }).catch(console.error);

            res.json({ success: true, message: 'An tura code zuwa email dinka cikin hanzari!' });
        });
    });
});

// Create Project after OTP verification
app.post('/api/projects/create', (req, res) => {
    const { email, code, projectName, password } = req.body;

    db.get(`SELECT * FROM otps WHERE email = ? AND code = ? AND is_used = 0 ORDER BY id DESC LIMIT 1`, [email, code], (err, otpRow) => {
        if (!otpRow || new Date() > new Date(otpRow.expires_at)) {
            return res.status(400).json({ error: 'Code din ya lalace ko bai da tabbas, ko kuma lokacinsa ya wuce (Minti daya ya cika).' });
        }

        // Mark OTP as used (Useless now)
        db.run(`UPDATE otps SET is_used = 1 WHERE id = ?`, [otpRow.id]);

        // Check if project name already exists
        db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existingProj) => {
            if (existingProj) {
                return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan a wani project din. Da fatan a zabi wani sunan.' });
            }

            const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
            const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

            db.run(`INSERT INTO projects (owner_email, name, project_id, api_key) VALUES (?, ?, ?, ?)`,
                [email, projectName, project_id, api_key], function(err) {
                    if (err) return res.status(500).json({ error: err.message });

                    // Send Welcome Message
                    transporter.sendMail({
                        from: 'Sirdique Storage <abubakarsadeeq8533@gmail.com>',
                        to: email,
                        subject: 'Barka da zuwa Sirdique Storage!',
                        text: `Murna ce da samun nasarar kirkirar project dinka: ${projectName}.\nProject ID: ${project_id}\nAPI Key: ${api_key}\n\nPowered by Sirdique`
                    }).catch(console.error);

                    res.json({ success: true, project_id, api_key, name: projectName });
                });
        });
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

// Storage API with 800MB limit & Image Compression
app.post('/api/save', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { title, content } = req.body;
        let file_url = null;
        let fileSize = 0;

        if (req.file) {
            fileSize = req.file.buffer.length;
            if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
                return res.status(400).json({ error: 'Storage Limit Exceeded! Kowanne project yana da limit na 800MB ne kacal.' });
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
                
                // Update used storage
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

// --- EXTERNAL WEBSITE AUTH (Sign Up & Login with Custom Website Name Support) ---

app.post('/api/auth/signup', verifyApiKey, (req, res) => {
    const { email, password, websiteName } = req.body;
    db.get(`SELECT * FROM app_users WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err, user) => {
        if (user) return res.status(400).json({ error: 'Email already registered for this project' });

        db.run(`INSERT INTO app_users (project_id, email, password, is_verified) VALUES (?, ?, ?, 0)`,
            [req.project.project_id, email, password], function(err) {
                if (err) return res.status(500).json({ error: err.message });

                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const expiresAt = new Date(Date.now() + 1 * 60000).toISOString(); // 1 min

                db.run(`INSERT INTO otps (email, code, expires_at, is_used) VALUES (?, ?, ?, 0)`, [email, otp, expiresAt], () => {
                    const senderName = websiteName || req.project.name || 'Sirdique Partner Website';
                    transporter.sendMail({
                        from: `${senderName} <abubakarsadeeq8533@gmail.com>`,
                        to: email,
                        subject: `${senderName} - Sign Up Confirmation Code`,
                        text: `Sannu! Lambar tabbatar da shiga (Sign Up confirmation code) ta ${senderName} ita ce: ${otp}\n\nWannan lambar za ta mutu bayan minti daya (1 minute).\n\nPowered by Sirdique`
                    }).catch(console.error);

                    res.json({ success: true, message: 'An tura code zuwa email dinka cikin hanzari!' });
                });
            });
    });
});

app.post('/api/auth/verify-otp', verifyApiKey, (req, res) => {
    const { email, code } = req.body;
    db.get(`SELECT * FROM otps WHERE email = ? AND code = ? AND is_used = 0 ORDER BY id DESC LIMIT 1`, [email, code], (err, otpRow) => {
        if (!otpRow || new Date() > new Date(otpRow.expires_at)) {
            return res.status(400).json({ error: 'Invalid or expired OTP (Minti daya ya wuce ko kuma an riga an yi amfani da shi).' });
        }

        db.run(`UPDATE otps SET is_used = 1 WHERE id = ?`, [otpRow.id]);
        db.run(`UPDATE app_users SET is_verified = 1 WHERE email = ? AND project_id = ?`, [email, req.project.project_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Account verified successfully 100%!' });
        });
    });
});

// Login with strict Brute-force protection (3 attempts -> 5 mins, then up to 24 hours)
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
            } else if (attempts >= 6) {
                lockTime = new Date(now.getTime() + 5 * 60000).toISOString(); // 5 mins
            } else if (attempts >= 3) {
                lockTime = new Date(now.getTime() + 5 * 60000).toISOString(); // 5 mins
            }

            db.run(`UPDATE app_users SET failed_attempts = ?, lock_until = ? WHERE id = ?`, [attempts, lockTime, user.id]);
            return res.status(400).json({ error: `Incorrect password. Attempt ${attempts}/9. (3 kuskure suna kulle account na mintina 5, sannan awa 24)` });
        }

        if (user.is_verified === 0) {
            return res.status(401).json({ error: 'Please verify your email first using the confirmation code' });
        }

        db.run(`UPDATE app_users SET failed_attempts = 0, lock_until = NULL WHERE id = ?`, [user.id]);
        res.json({ success: true, message: 'Login successful', email: user.email });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Storage Server running on port ${PORT}`));
