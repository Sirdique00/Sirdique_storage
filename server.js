const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(cors());
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
        last_login DATETIME,
        status TEXT DEFAULT 'Active'
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
        status_mode TEXT DEFAULT 'live',
        used_storage INTEGER DEFAULT 0,
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

    db.run(`CREATE TABLE IF NOT EXISTS buckets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT,
        bucket_name TEXT,
        is_enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

const verifyApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    if (!apiKey) return res.status(401).json({ error: 'API Key is missing.' });

    db.get(`SELECT * FROM projects WHERE api_key = ?`, [apiKey], (err, project) => {
        if (err || !project) return res.status(403).json({ error: 'Invalid API Key.' });
        req.project = project;
        next();
    });
};

// AUTH
app.post('/api/hub/send-code', (req, res) => {
    const { email, type } = req.body;
    if(!email) return res.status(400).json({ error: 'Sanya email din ka.' });

    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if(type === 'signup' && user) return res.status(400).json({ error: 'An riga an yi rijista da wannan email din.' });
        if(type === 'forgot' && !user) return res.status(400).json({ error: 'Babu account da ke da wannan email din.' });
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires_at = Date.now() + 2 * 60 * 1000;

        db.run(`DELETE FROM verification_codes WHERE email = ? AND type = ?`, [email, type], () => {
            db.run(`INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)`, 
                [email, code, type, expires_at], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, code });
                });
        });
    });
});

app.post('/api/hub/verify-and-register', (req, res) => {
    const { email, password, code } = req.body;
    db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = 'signup' ORDER BY id DESC LIMIT 1`, [email], (err, record) => {
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa.' });
        if (record.code !== code) return res.status(400).json({ error: 'Code din bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]);
        db.run(`INSERT INTO hub_users (email, password, status, last_login) VALUES (?, ?, 'Active', CURRENT_TIMESTAMP)`, [email, password], function(err) {
            if (err) return res.status(400).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

app.post('/api/hub/verify-and-reset', (req, res) => {
    const { email, newPassword, code } = req.body;
    db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = 'forgot' ORDER BY id DESC LIMIT 1`, [email], (err, record) => {
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa.' });
        if (record.code !== code) return res.status(400).json({ error: 'Code din bai daidai ba.' });

        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]);
        db.run(`UPDATE hub_users SET password = ?, failed_attempts = 0, ban_until = 0 WHERE email = ?`, [newPassword, email], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'An sauya password din da nasara!' });
        });
    });
});

app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email din nan bai wanzu ba.' });
        
        if (user.ban_until && Date.now() < user.ban_until) {
            const minsLeft = Math.ceil((user.ban_until - Date.now()) / 60000);
            return res.status(403).json({ error: `An yi ban na wucin gadi saboda kuskuren password. Sake gwadawa bayan minti ${minsLeft}.` });
        }

        if (user.status === 'Suspended') {
            return res.status(403).json({ error: 'An dakatar da wannan account din.' });
        }

        if (user.password !== password) {
            const newAttempts = (user.failed_attempts || 0) + 1;
            if (newAttempts >= 3) {
                const banTime = Date.now() + 30 * 60 * 1000;
                db.run(`UPDATE hub_users SET failed_attempts = ?, ban_until = ? WHERE email = ?`, [newAttempts, banTime, email]);
                return res.status(403).json({ error: 'Kayi kuskuren password sau 3. An yi ban na tsawon minti 30!' });
            } else {
                db.run(`UPDATE hub_users SET failed_attempts = ? WHERE email = ?`, [newAttempts, email]);
                return res.status(400).json({ error: `Password ba daidai ba ne. Sauran kuskure ${3 - newAttempts}.` });
            }
        }

        db.run(`UPDATE hub_users SET failed_attempts = 0, ban_until = 0, last_login = CURRENT_TIMESTAMP WHERE email = ?`, [email]);
        res.json({ success: true, email: user.email, isAdmin: email === 'abubakarsadeeq8533@gmail.com' });
    });
});

// PROJECTS MANAGEMENT & RENAME / DELETE
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    if(!projectName) return res.status(400).json({ error: 'Sanya sunan project.' });

    db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'An riga an yi amfani da wannan sunan.' });

        const project_id = 'PRJ-' + Math.random().toString(36).substring(2, 9).toUpperCase();
        const api_key = 'sd-' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

        db.run(`INSERT INTO projects (owner_email, name, project_id, api_key, status_mode) VALUES (?, ?, ?, ?, 'live')`,
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

// RENAME PROJECT
app.post('/api/projects/rename', (req, res) => {
    const { project_id, newName } = req.body;
    if(!newName) return res.status(400).json({ error: 'Sanya sabon suna.' });

    db.run(`UPDATE projects SET name = ? WHERE project_id = ?`, [newName, project_id], function(err) {
        if (err) return res.status(500).json({ error: 'Sunan yana da shi a wani project din.' });
        res.json({ success: true });
    });
});

// PERMANENT DELETE PROJECT (Clears Storage & Keys)
app.post('/api/projects/delete', (req, res) => {
    const { project_id } = req.body;
    if(!project_id) return res.status(400).json({ error: 'Babu project ID.' });

    // Delete associated files from disk
    db.all(`SELECT file_url FROM bucket_files WHERE project_id = ?`, [project_id], (err, files) => {
        if(files) {
            files.forEach(f => {
                const filePath = path.join(__dirname, f.file_url);
                if(fs.existsSync(filePath)) fs.unlinkSync(filePath);
            });
        }
        // Delete from all tables
        db.run(`DELETE FROM projects WHERE project_id = ?`, [project_id]);
        db.run(`DELETE FROM project_tables WHERE project_id = ?`, [project_id]);
        db.run(`DELETE FROM project_rows WHERE project_id = ?`, [project_id]);
        db.run(`DELETE FROM buckets WHERE project_id = ?`, [project_id]);
        db.run(`DELETE FROM bucket_files WHERE project_id = ?`, [project_id], () => {
            res.json({ success: true, message: 'An goge project din da duk bayanan sa baki daya.' });
        });
    });
});

// BUCKETS & TABLES & AI
app.post('/api/buckets/create', verifyApiKey, (req, res) => {
    const { bucketName } = req.body;
    db.run(`INSERT INTO buckets (project_id, bucket_name, is_enabled) VALUES (?, ?, 1)`, [req.project.project_id, bucketName], (err) => {
        if (err) return res.status(500).json({ error: 'Kuskure ya faru.' });
        res.json({ success: true });
    });
});

app.get('/api/buckets/list', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM buckets WHERE project_id = ?`, [req.project.project_id], (err, buckets) => {
        res.json({ success: true, buckets });
    });
});

app.post('/api/buckets/toggle', verifyApiKey, (req, res) => {
    const { bucketId, isEnabled } = req.body;
    db.run(`UPDATE buckets SET is_enabled = ? WHERE id = ? AND project_id = ?`, [isEnabled, bucketId, req.project.project_id], () => {
        res.json({ success: true });
    });
});

app.post('/api/database/tables', verifyApiKey, (req, res) => {
    const { tableName, columns, enableRls } = req.body;
    db.run(`INSERT INTO project_tables (project_id, table_name, columns) VALUES (?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, rls: enableRls ? 'Enabled' : 'Disabled' });
        });
});

app.post('/api/database/ai-create-table', verifyApiKey, (req, res) => {
    const { prompt } = req.body;
    let tableName = 'ai_custom_table';
    let columns = ['id', 'title', 'created_at'];

    const lower = prompt.toLowerCase();
    if (lower.includes('user') || lower.includes('mutum')) {
        tableName = 'users_table';
        columns = ['name', 'email', 'phone'];
    } else if (lower.includes('product') || lower.includes('kaya')) {
        tableName = 'products_table';
        columns = ['product_name', 'price', 'category'];
    } else {
        const words = prompt.replace(/[^a-zA-Z0-9 ]/g, '').split(' ');
        if(words.length > 0 && words[0]) tableName = words[0].toLowerCase() + '_tbl';
    }

    db.run(`INSERT INTO project_tables (project_id, table_name, columns) VALUES (?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
            if (err) return res.json({ success: false, message: 'Teburin yana da shi a baya.' });
            res.json({ success: true, tableName, columns, message: `An kirkiro tebur "${tableName}" da nasara!` });
        });
});

app.get('/api/database/tables', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM project_tables WHERE project_id = ?`, [req.project.project_id], (err, tables) => {
        res.json({ success: true, tables });
    });
});

app.post('/api/database/rows', verifyApiKey, (req, res) => {
    const { tableName, rowData } = req.body;
    db.run(`INSERT INTO project_rows (project_id, table_name, row_data) VALUES (?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(rowData)], () => {
            res.json({ success: true });
        });
});

app.get('/api/database/rows/:tableName', verifyApiKey, (req, res) => {
    const { tableName } = req.params;
    db.all(`SELECT * FROM project_rows WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, rows) => {
        res.json({ success: true, rows });
    });
});

app.post('/api/bucket/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { bucketName } = req.body;
        db.get(`SELECT * FROM buckets WHERE project_id = ? AND bucket_name = ?`, [req.project.project_id, bucketName], async (err, bucket) => {
            if (!bucket || bucket.is_enabled === 0) return res.status(403).json({ error: 'Bucket a kashe yake.' });

            const fileSize = req.file.buffer.length;
            const filename = `img-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
            const filepath = path.join(uploadsDir, filename);

            await sharp(req.file.buffer).resize({ width: 1000, withoutEnlargement: true }).webp({ quality: 80 }).toFile(filepath);

            const file_url = `/uploads/${filename}`;
            db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
                [req.project.project_id, bucketName, file_url, req.file.originalname, fileSize], () => {
                    db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                    res.json({ success: true, file_url });
                });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/bucket/files/:bucketName', verifyApiKey, (req, res) => {
    const { bucketName } = req.params;
    db.all(`SELECT * FROM bucket_files WHERE project_id = ? AND bucket_name = ? ORDER BY id DESC`, [req.project.project_id, bucketName], (err, files) => {
        res.json({ success: true, files });
    });
});

// ADMIN
app.get('/api/admin/stats', (req, res) => {
    db.get(`SELECT COUNT(*) as totalUsers FROM hub_users`, (err, uRow) => {
        db.get(`SELECT COUNT(*) as totalProjects FROM projects`, (err, pRow) => {
            db.all(`SELECT * FROM hub_users`, (err, users) => {
                db.all(`SELECT * FROM projects`, (err, projects) => {
                    res.json({ success: true, totalUsers: uRow.totalUsers, totalProjects: pRow.totalProjects, users, projects });
                });
            });
        });
    });
});

app.post('/api/admin/user-action', (req, res) => {
    const { email, action } = req.body;
    let newStatus = action === 'suspend' ? 'Suspended' : 'Active';
    if(action === 'forceout') {
        db.run(`UPDATE hub_users SET failed_attempts = 3 WHERE email = ?`, [email], () => res.json({ success: true }));
        return;
    }
    db.run(`UPDATE hub_users SET status = ? WHERE email = ?`, [newStatus, email], () => res.json({ success: true }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Cloud Storage Server running on port ${PORT}`));
