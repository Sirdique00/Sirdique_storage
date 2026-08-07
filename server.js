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
        columns TEXT,
        rls_enabled INTEGER DEFAULT 1
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
        if (err || !project) return res.status(403).json({ error: 'Invalid or fake API Key.' });
        req.project = project;
        next();
    });
};

// AUTHENTICATION & SECURITY
app.post('/api/hub/send-code', (req, res) => {
    const { email, type } = req.body;
    if(!email) return res.status(400).json({ error: 'Email is required.' });

    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if(type === 'signup' && user) return res.status(400).json({ error: 'Email already registered.' });
        if(type === 'forgot' && !user) return res.status(400).json({ error: 'No account found with this email.' });
        
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
        if (!record || Date.now() > record.expires_at || record.code !== code) {
            return res.status(400).json({ error: 'Invalid or expired verification code.' });
        }
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
        if (!record || Date.now() > record.expires_at || record.code !== code) {
            return res.status(400).json({ error: 'Invalid or expired code.' });
        }
        db.run(`DELETE FROM verification_codes WHERE id = ?`, [record.id]);
        db.run(`UPDATE hub_users SET password = ?, failed_attempts = 0, ban_until = 0 WHERE email = ?`, [newPassword, email], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Password successfully updated!' });
        });
    });
});

app.post('/api/hub/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM hub_users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Email does not exist.' });
        if (user.ban_until && Date.now() < user.ban_until) {
            return res.status(403).json({ error: 'Account temporarily locked due to failed attempts.' });
        }
        if (user.status === 'Suspended') return res.status(403).json({ error: 'Account suspended.' });

        if (user.password !== password) {
            const newAttempts = (user.failed_attempts || 0) + 1;
            if (newAttempts >= 3) {
                db.run(`UPDATE hub_users SET failed_attempts = ?, ban_until = ? WHERE email = ?`, [newAttempts, Date.now() + 30*60*1000, email]);
                return res.status(403).json({ error: 'Account locked for 30 minutes.' });
            }
            db.run(`UPDATE hub_users SET failed_attempts = ? WHERE email = ?`, [newAttempts, email]);
            return res.status(400).json({ error: 'Incorrect password.' });
        }

        db.run(`UPDATE hub_users SET failed_attempts = 0, ban_until = 0, last_login = CURRENT_TIMESTAMP WHERE email = ?`, [email]);
        res.json({ success: true, email: user.email, isAdmin: email === 'abubakarsadeeq8533@gmail.com' });
    });
});

// PROJECT CRUD
app.post('/api/projects/create', (req, res) => {
    const { email, projectName } = req.body;
    if(!projectName) return res.status(400).json({ error: 'Project name required.' });

    db.get(`SELECT * FROM projects WHERE name = ?`, [projectName], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'Project name already exists.' });

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

app.post('/api/projects/rename', (req, res) => {
    const { projectId, newName } = req.body;
    db.run(`UPDATE projects SET name = ? WHERE project_id = ?`, [newName, projectId], (err) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.post('/api/projects/delete', (req, res) => {
    const { projectId } = req.body;
    db.serialize(() => {
        db.run(`DELETE FROM project_rows WHERE project_id = ?`, [projectId]);
        db.run(`DELETE FROM project_tables WHERE project_id = ?`, [projectId]);
        db.run(`DELETE FROM bucket_files WHERE project_id = ?`, [projectId]);
        db.run(`DELETE FROM buckets WHERE project_id = ?`, [projectId]);
        db.run(`DELETE FROM projects WHERE project_id = ?`, [projectId], (err) => {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

// UNIVERSAL SINGLE ENDPOINT (EXECUTE API: insert row, upload file, etc.)
app.post('/api/v1/execute', verifyApiKey, upload.single('file'), async (req, res) => {
    try {
        const { action, tableName, rowData, bucketName } = req.body;

        // 1. File Upload Action
        if (action === 'upload' || req.file) {
            const bName = bucketName || 'default';
            db.get(`SELECT * FROM buckets WHERE project_id = ? AND bucket_name = ?`, [req.project.project_id, bName], async (err, bucket) => {
                if (!bucket) {
                    // Auto create bucket if missing
                    db.run(`INSERT INTO buckets (project_id, bucket_name, is_enabled) VALUES (?, ?, 1)`, [req.project.project_id, bName]);
                }
                const fileSize = req.file.buffer.length;
                const filename = `img-${Date.now()}-${Math.round(Math.random() * 1000)}.webp`;
                const filepath = path.join(uploadsDir, filename);

                await sharp(req.file.buffer)
                    .resize({ width: 1000, withoutEnlargement: true })
                    .webp({ quality: 80 })
                    .toFile(filepath);

                const file_url = `/uploads/${filename}`;
                db.run(`INSERT INTO bucket_files (project_id, bucket_name, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
                    [req.project.project_id, bName, file_url, req.file.originalname, fileSize], function(err) {
                        db.run(`UPDATE projects SET used_storage = used_storage + ? WHERE project_id = ?`, [fileSize, req.project.project_id]);
                        res.json({ success: true, file_url });
                    });
            });
            return;
        }

        // 2. Database Insert Row Action
        if (tableName && rowData) {
            const parsedData = typeof rowData === 'string' ? JSON.parse(rowData) : rowData;
            db.run(`INSERT INTO project_rows (project_id, table_name, row_data) VALUES (?, ?, ?)`,
                [req.project.project_id, tableName, JSON.stringify(parsedData)], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Row inserted successfully.' });
                });
            return;
        }

        res.status(400).json({ error: 'Invalid execution payload.' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// BACKWARD COMPATIBLE ENDPOINTS FOR DASHBOARD & SDK
app.post('/api/buckets/create', verifyApiKey, (req, res) => {
    const { bucketName } = req.body;
    db.run(`INSERT INTO buckets (project_id, bucket_name, is_enabled) VALUES (?, ?, 1)`, [req.project.project_id, bucketName], (err) => {
        if (err) return res.status(500).json({ error: err.message });
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
    db.run(`UPDATE buckets SET is_enabled = ? WHERE id = ? AND project_id = ?`, [isEnabled, bucketId, req.project.project_id], (err) => {
        res.json({ success: true });
    });
});

app.post('/api/database/tables', verifyApiKey, (req, res) => {
    const { tableName, columns, enableRls } = req.body;
    db.run(`INSERT INTO project_tables (project_id, table_name, columns, rls_enabled) VALUES (?, ?, ?, ?)`,
        [req.project.project_id, tableName, JSON.stringify(columns), enableRls ? 1 : 0], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
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
        [req.project.project_id, tableName, JSON.stringify(rowData)], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

app.get('/api/database/rows/:tableName', verifyApiKey, (req, res) => {
    const { tableName } = req.params;
    db.all(`SELECT * FROM project_rows WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tableName], (err, rows) => {
        res.json({ success: true, rows });
    });
});

// ADVANCED MULTILINGUAL AI PROMPT GENERATOR (Hausa & English / Multiple tables & RLS control)
app.post('/api/database/ai-create-table', verifyApiKey, (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt required.' });

    const lower = prompt.toLowerCase();

    // Handle Drop / Delete table instructions in Hausa & English
    if (lower.includes('delete') || lower.includes('drop') || lower.includes('goge') || lower.includes('cire')) {
        db.all(`SELECT table_name FROM project_tables WHERE project_id = ?`, [req.project.project_id], (err, tables) => {
            let targets = [];
            tables.forEach(t => {
                if (lower.includes(t.table_name.toLowerCase())) targets.push(t.table_name);
            });
            if (targets.length > 0) {
                targets.forEach(tbl => {
                    db.run(`DELETE FROM project_rows WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tbl]);
                    db.run(`DELETE FROM project_tables WHERE project_id = ? AND table_name = ?`, [req.project.project_id, tbl]);
                });
                return res.json({ success: true, message: `AI successfully deleted table(s): ${targets.join(', ')}.` });
            }
            return res.json({ success: false, message: 'AI could not find matching table to delete.' });
        });
        return;
    }

    // Handle RLS Toggle (kunna/kashe RLS) via prompt
    if (lower.includes('rls') || lower.includes('tsaro')) {
        db.all(`SELECT table_name FROM project_tables WHERE project_id = ?`, [req.project.project_id], (err, tables) => {
            let targetTbl = null;
            tables.forEach(t => { if (lower.includes(t.table_name.toLowerCase())) targetTbl = t.table_name; });

            if (targetTbl) {
                let enable = (lower.includes('kunna') || lower.includes('enable') || lower.includes('on')) ? 1 : 0;
                db.run(`UPDATE project_tables SET rls_enabled = ? WHERE project_id = ? AND table_name = ?`, [enable, req.project.project_id, targetTbl], () => {
                    return res.json({ success: true, message: `AI successfully updated RLS for "${targetTbl}" to ${enable ? 'Enabled' : 'Disabled'}.` });
                });
                return;
            }
        });
    }

    // Multi-table creation parsing for student, code, class (Hausa & English)
    let createdTables = [];
    
    // Explicit multi-table check as requested
    if (lower.includes('student') || lower.includes('dalibi') || lower.includes('class') || lower.includes('code')) {
        const tablesToCreate = [
            { name: 'class', cols: ['class_id', 'class_name', 'grade'], rls: 1 },
            { name: 'students', cols: ['student_id', 'full_name', 'age', 'class_assigned'], rls: 1 },
            { name: 'code', cols: ['code_id', 'snippet', 'status'], rls: 0 }
        ];

        let count = 0;
        tablesToCreate.forEach(t => {
            db.get(`SELECT * FROM project_tables WHERE project_id = ? AND table_name = ?`, [req.project.project_id, t.name], (err, existing) => {
                if (!existing) {
                    db.run(`INSERT INTO project_tables (project_id, table_name, columns, rls_enabled) VALUES (?, ?, ?, ?)`,
                        [req.project.project_id, t.name, JSON.stringify(t.cols), t.rls], () => {
                            createdTables.push(t.name);
                            count++;
                            if (count === tablesToCreate.length) {
                                res.json({ success: true, message: `AI successfully created tables: ${createdTables.join(', ')} with respective RLS rules!` });
                            }
                        });
                } else {
                    count++;
                    if (count === tablesToCreate.length) {
                        res.json({ success: true, message: `AI processed tables successfully.` });
                    }
                }
            });
        });
        return;
    }

    // Generic AI Single Table Fallback
    let tableName = 'custom_ai_tbl';
    let columns = ['id', 'name', 'created_at'];
    const words = prompt.replace(/[^a-zA-Z0-9 ]/g, '').split(' ');
    if(words.length > 0 && words[0]) tableName = words[0].toLowerCase() + '_table';

    db.run(`INSERT INTO project_tables (project_id, table_name, columns, rls_enabled) VALUES (?, ?, ?, 1)`,
        [req.project.project_id, tableName, JSON.stringify(columns)], function(err) {
            if (err) return res.json({ success: false, message: 'Table already exists or invalid prompt.' });
            res.json({ success: true, message: `AI successfully created table "${tableName}".` });
        });
});

// ADMIN STATS
app.get('/api/admin/stats', (req, res) => {
    db.get(`SELECT COUNT(*) as totalUsers FROM hub_users`, (err, uRow) => {
        db.get(`SELECT COUNT(*) as totalProjects FROM projects`, (err, pRow) => {
            db.get(`SELECT SUM(used_storage) as totalStorage FROM projects`, (err, sRow) => {
                db.all(`SELECT * FROM hub_users`, (err, users) => {
                    db.all(`SELECT * FROM projects`, (err, projects) => {
                        res.json({
                            success: true,
                            totalUsers: uRow.totalUsers,
                            totalProjects: pRow.totalProjects,
                            totalStorage: sRow.totalStorage || 0,
                            users,
                            projects
                        });
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
            return res.json({ success: true, message: 'User forced out.' });
        });
        return;
    }
    db.run(`UPDATE hub_users SET status = ? WHERE email = ?`, [newStatus, email], (err) => {
        res.json({ success: true });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sirdique Cloud Storage Server running on port ${PORT}`));
