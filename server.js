const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use(express.static('.')); // Wannan yana sa index.html yayi aiki a waje tare da server.js

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads';
        if (!fs.existsSync(uploadDir)){
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, 'sirdique-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

const dbFile = './database.sqlite';
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Kuskure:', err.message);
    else console.log('Sirdique Database yana aiki.');
});

db.run(`CREATE TABLE IF NOT EXISTS sirdique_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,
    filePath TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.post('/api/save', upload.single('file'), (req, res) => {
    const { title, content } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : null;

    const query = `INSERT INTO sirdique_data (title, content, filePath) VALUES (?, ?, ?)`;
    db.run(query, [title, content, filePath], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: 'An ajiye a Sirdique Storage!', id: this.lastID, filePath });
    });
});

app.get('/api/data', (req, res) => {
    db.all(`SELECT * FROM sirdique_data ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, data: rows });
    });
});

app.listen(PORT, () => {
    console.log(`Sirdique Storage tana gudu a Port ${PORT}`);
});

