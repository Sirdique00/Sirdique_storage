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

// 1. AUTHENTICATION & SECURITY (With strict Forgot Password Email Check)
app.post('/api/hub/send-code', (req, res) => {
    const { email, type } = req.body;
    if(!email) return res.status(400).json({ error: 'Sanya email din ka.' });

    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if(type === 'signup' && user) return res.status(400).json({ error: 'An riga an yi rijista da wannan email din. Ka yi Sign In.' });
        if(type === 'forgot' && !user) return res.status(400).json({ error: 'Babu wani account da aka taba kirkira da wannan email din.' });
        
        // Check if there's an unexpired code already to prevent spamming
        db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = ? AND expires_at > ?`, [email, type, Date.now()], (err, existingCode) => {
            if (existingCode) {
                const timeLeft = Math.ceil((existingCode.expires_at - Date.now()) / 1000);
                return res.json({ success: true, code: existingCode.code, expires_at: existingCode.expires_at, reused: true });
            }

            const code = Math.floor(100000 + Math.random() * 900000).toString();
            const expires_at = Date.now() + 2 * 60 * 1000;

            db.run(`DELETE FROM verification_codes WHERE email = ? AND type = ?`, [email, type], () => {
                db.run(`INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)`, 
                    [email, code, type, expires_at], (err) => {
                        if (err) return res.status(500).json({ error: err.message });
                        res.json({ success: true, code, expires_at, reused: false });
                    });
            });
        });
    });
});

app.post('/api/hub/verify-and-register', (req, res) => {
    const { email, password, code } = req.body;
    db.get(`SELECT * FROM verification_codes WHERE email = ? AND type = 'signup' ORDER BY id DESC LIMIT 1`, [email], (err, record) => {
        if (!record) return res.status(400).json({ error: 'Babu wani code da aka tura.' });
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa (Expired).' });
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
        if (Date.now() > record.expires_at) return res.status(400).json({ error: 'Wannan code din ya wuce lokacinsa (Expired).' });
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
        if (!user) return res.status(400).json({ error: 'Email din nan bai wanzu ba. Yi Sign Up.' });
        
        if (user.ban_until && Date.now() < user.ban_until) {
            const minsLeft = Math.ceil((user.ban_until - Date.now()) / 60000);
            return res.status(403).json({ error: `An yi ban na wucin gadi saboda kuskuren password sau 3. Sake gwadawa bayan minti ${minsLeft}.` });
        }

        if (user.status === 'Suspended') {
            return res.status(403).json({ error: 'An dakatar da wannan account din (Suspended).' });
        }

        if (user.password !== password) {
            const newAttempts = (user.failed_attempts || 0) + 1;
            if (newAttempts >= 3) {
                const banTime = Date.now() + 30 * 60 * 1000;
                db.run(`UPDATE hub_users SET failed_attempts = ?, ban_until = ? WHERE email = ?`, [newAttempts, banTime, email]);
                return res.status(403).json({ error: 'Kayi kuskuren password sau 3. An yi ban na tsawon minti 30!' });
            } else {
                db.run(`UPDATE hub_users SET failed_attempts = ? WHERE email = ?`, [newAttempts, email]);
                return res.status(400).json({ error: `Password ba daidai ba ne. Sauran kuskure ${3 - newAttempts} kafin a yi ban.` });
            }
        }

        db.run(`UPDATE hub_users SET failed_attempts = 0, ban_until = 0, last_login = CURRENT_TIMESTAMP WHERE email = ?`, [email]);
        res.json({ success: true, email: user.email, isAdmin: email === 'abubakarsadeeq8533@gmail.com' });
    });
});

// 2. PROJECT MANAGEMENT
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

// 3. STORAGE BUCKETS
app.post('/api/buckets/create', verifyApiKey, (req, res) => {
    const { bucketName } = req.body;
    if(!bucketName) return res.status(400).json({ error: 'Sanya sunan bucket.' });

    db.run(`INSERT INTO buckets (project_id, bucket_name, is_enabled) VALUES (?, ?, 1)`, [req.project.project_id, bucketName], (err) => {
        if (err) return res.status(500).json({ error: 'Bucket din yana da shi ko kuskure ya faru.' });
        res.json({ success: true });
    });
});

app.get('/api/buckets/list', verifyApiKey, (req, res) => {
    db.all(`SELECT * FROM buckets WHERE project_id = ?`, [req.project.project_id], (err, buckets) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, buckets });
    });
});

app.post('/api/buckets/toggle', verifyApiKey, (req, res) => {
    const { bucketId, isEnabled } = req.body;
    db.run(`UPDATE buckets SET is_enabled = ? WHERE id = ? AND project_id = ?`, [isEnabled, bucketId, req.project.project_id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// 4. DATABASE TABLES & AI PROMPT TABLE CREATOR
app.post('/api/database/tables', verifyApiKey, (req, res) => {
    const { tableName, columns, enableRls } = req.body;
    if(!tableName || !columns || columns.length === 0) return res.status(400).json({ error: 'Table name and columns are required.' });

    db.get(`SELECT * FROM project_tables WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, table) => {
        if (table) {
            let existingCols = JSON.parse(table.columns);
            let mergedCols = Array.from(new Set([...existingCols, ...columns]));
            db.run(`UPDATE project_tables SET columns = ? WHERE id = ?`, [JSON.stringify(mergedCols), table.id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, message: 'Table columns updated successfully.' });
            });
        } else {
            db.run(`INSERT INTO project_tables (project_id, table_name, columns) VALUES (?, ?, ?)`,
                [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, rls: enableRls ? 'Enabled' : 'Disabled' });
                });
        }
    });
});

// AI Prompt to Table Converter endpoint
app.post('/api/database/ai-table', verifyApiKey, (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required.' });

    const lower = prompt.toLowerCase();
    let tableName = 'custom_table_' + Math.floor(Math.random() * 1000);
    let columns = ['name', 'created_at'];

    if (lower.includes('order') || lower.includes('customer')) {
        tableName = 'customer_orders';
        columns = ['customer_name', 'item', 'price', 'phone'];
    } else if (lower.includes('user') || lower.includes('profile')) {
        tableName = 'users_profile';
        columns = ['username', 'email', 'status'];
    } else if (lower.includes('product') || lower.includes('store') || lower.includes('item')) {
        tableName = 'store_products';
        columns = ['product_name', 'price', 'stock', 'category'];
    } else {
        // Extract words as columns
        const words = prompt.replace(/[^a-zA-Z0-9 ]/g, '').split(' ').filter(w => w.length > 2);
        if (words.length > 0) {
            tableName = words[0] + '_data';
            columns = words.slice(1, 5);
            if (columns.length === 0) columns = ['title', 'description'];
        }
    }

    db.get(`SELECT * FROM project_tables WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, table) => {
        if (table) {
            res.json({ success: true, tableName, columns: JSON.parse(table.columns), message: `AI successfully matched existing table: ${tableName}` });
        } else {
            db.run(`INSERT INTO project_tables (project_id, table_name, columns) VALUES (?, ?, ?)`,
                [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, tableName, columns, message: `AI successfully generated table '${tableName}' with columns!` });
                });
        }
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

// 5. BUCKET UPLOAD WITH WEBP COMPRESSION
app.post('/api/bucket/upload', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { bucketName } = req.body;
        if (!req.file || !bucketName) return res.status(400).json({ error: 'Sanya bucket name da fayil.' });

        db.get(`SELECT * FROM buckets WHERE project_id = ? AND bucket_name = ?`, [req.project.project_id, bucketName], async (err, bucket) => {
            if (!bucket || bucket.is_enabled === 0) {
                return res.status(403).json({ error: 'Wannan bucket din a kashe yake (Disabled) ko bai wanzu ba.' });
            }

            const fileSize = req.file.buffer.length;
            if (req.project.used_storage + fileSize > 800 * 1024 * 1024) {
                return res.status(400).json({ error: 'Storage Limit Exceeded (800MB).' });
            }

            const filename = `img-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
            const filepath = path.join(uploadsDir, filename);

            await sharp(req.file.buffer)
                .resize({ width: 1000, withoutEnlargement: true })
                .webp({ quality: 80 })
                .toFile(filepath);

            const file_url = `/uploads/${filename}`;
            db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
                [req.project.project_id, bucketName, file_url, req.file.originalname, fileSize], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
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
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, files });
    });
});

// 6. ADMIN API ENDPOINTS
app.get('/api/admin/stats', (req, res) => {
    db.get(`SELECT COUNT(*) as totalUsers FROM hub_users`, (err, uRow) => {
        db.get(`SELECT COUNT(*) as totalProjects FROM projects`, (err, pRow) => {
            db.all(`SELECT * FROM hub_users`, (err, users) => {
                db.all(`SELECT * FROM projects`, (err, projects) => {
                    res.json({
                        success: true,
                        totalUsers: uRow.totalUsers,
                        totalProjects: pRow.totalProjects,
                        users,
                        projects
                    });
                });
            });
        });
    });
});

app.post('/api/admin/user-action', (req, res) => {
    const { email, action } = req.body;
    let newStatus = action === 'suspend' ? 'Suspended' : 'Active';
    if(action === 'forceout') {
        db.run(`UPDATE hub_users SET failed_attempts = 3 WHERE email = ?`, [email], () => {
            return res.json({ success: true, message: 'An cire user din (Force out).' });
        });
        return;
    }
    db.run(`UPDATE hub_users SET status = ? WHERE email = ?`, [newStatus, email], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Cloud Storage Server running on port ${PORT}`));
