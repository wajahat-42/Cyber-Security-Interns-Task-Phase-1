const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 3000;

// Database setup
const db = new sqlite3.Database(':memory:');

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        password TEXT,
        profile TEXT
    )`);
    
    // Insert test data with weak passwords (plaintext)
    db.run(`INSERT INTO users (username, email, password, profile) VALUES 
        ('admin', 'admin@example.com', 'admin123', 'System Administrator'),
        ('user1', 'user1@example.com', 'password123', 'Regular User'),
        ('testuser', 'test@test.com', 'test123', 'Test Account')`);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    secret: 'weak-secret-key',
    resave: false,
    saveUninitialized: true
}));

app.set('view engine', 'ejs');

// VULNERABLE: No input sanitization
// Routes

// Home page
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});

// Signup page
app.get('/signup', (req, res) => {
    res.render('signup', { error: null, message: null });
});

// VULNERABLE: SQL Injection in signup
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABLE: Direct string concatenation in SQL query
    const query = `INSERT INTO users (username, email, password, profile) VALUES ('${username}', '${email}', '${password}', 'New User')`;
    
    db.run(query, function(err) {
        if (err) {
            res.render('signup', { error: 'Error creating account: ' + err.message, message: null });
        } else {
            res.render('signup', { error: null, message: 'Account created successfully!' });
        }
    });
});

// Login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// VULNERABLE: SQL Injection in login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: Direct string concatenation in SQL query
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, row) => {
        if (err) {
            res.render('login', { error: 'Database error' });
        } else if (row) {
            req.session.user = row;
            res.redirect('/profile');
        } else {
            res.render('login', { error: 'Invalid credentials' });
        }
    });
});

// Profile page
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('profile', { user: req.session.user });
});

// VULNERABLE: XSS in profile update
app.post('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    const { profile } = req.body;
    
    // VULNERABLE: No input sanitization
    db.run(`UPDATE users SET profile = '${profile}' WHERE id = ${req.session.user.id}`, (err) => {
        if (!err) {
            req.session.user.profile = profile;
        }
        res.redirect('/profile');
    });
});

// Search users (VULNERABLE to SQL Injection)
app.get('/search', (req, res) => {
    const { q } = req.query;
    
    // VULNERABLE: SQL Injection
    const query = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;
    
    db.all(query, (err, rows) => {
        if (err) {
            res.json({ error: err.message });
        } else {
            res.json({ users: rows });
        }
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});