const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const validator = require('validator');
const winston = require('winston');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console()
    ]
});

// Database setup
const db = new sqlite3.Database(':memory:');

// Create tables with hashed passwords
db.serialize(async () => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        profile TEXT
    )`);
    
    // Insert test data with hashed passwords
    const adminHash = await bcrypt.hash('admin123', SALT_ROUNDS);
    const user1Hash = await bcrypt.hash('password123', SALT_ROUNDS);
    const testHash = await bcrypt.hash('test123', SALT_ROUNDS);
    
    db.run(`INSERT INTO users (username, email, password, profile) VALUES 
        ('admin', 'admin@example.com', ?, 'System Administrator'),
        ('user1', 'user1@example.com', ?, 'Regular User'),
        ('testuser', 'test@test.com', ?, 'Test Account')`, 
        [adminHash, user1Hash, testHash]);
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.redirect('/login');
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            logger.warn('Invalid token attempt', { ip: req.ip });
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

app.set('view engine', 'ejs');

// Input sanitization helper
const sanitizeInput = (input) => {
    return validator.escape(input.trim());
};

// SECURE: Login with parameterized queries and bcrypt
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
        logger.warn('Login attempt with missing credentials', { ip: req.ip });
        return res.render('login', { error: 'Username and password required' });
    }
    
    if (!validator.isAlphanumeric(username)) {
        logger.warn('Login attempt with invalid username format', { ip: req.ip, username });
        return res.render('login', { error: 'Invalid username format' });
    }
    
    // SECURE: Parameterized query
    const query = 'SELECT * FROM users WHERE username = ?';
    
    db.get(query, [username], async (err, row) => {
        if (err) {
            logger.error('Database error during login', { error: err.message });
            return res.render('login', { error: 'Authentication failed' });
        }
        
        if (!row) {
            logger.warn('Login attempt for non-existent user', { ip: req.ip, username });
            return res.render('login', { error: 'Invalid credentials' });
        }
        
        // SECURE: Compare password with bcrypt
        const valid = await bcrypt.compare(password, row.password);
        if (!valid) {
            logger.warn('Failed login attempt', { ip: req.ip, username });
            return res.render('login', { error: 'Invalid credentials' });
        }
        
        // SECURE: Generate JWT
        const token = jwt.sign(
            { userId: row.id, username: row.username },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        logger.info('Successful login', { username, ip: req.ip });
        
        res.cookie('token', token, { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000
        });
        res.redirect('/profile');
    });
});

// SECURE: Signup with input validation and hashed passwords
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    
    // Validate inputs
    if (!username || !email || !password) {
        return res.render('signup', { error: 'All fields required', message: null });
    }
    
    if (!validator.isAlphanumeric(username)) {
        return res.render('signup', { error: 'Username must be alphanumeric', message: null });
    }
    
    if (!validator.isEmail(email)) {
        return res.render('signup', { error: 'Invalid email format', message: null });
    }
    
    if (password.length < 8) {
        return res.render('signup', { error: 'Password must be at least 8 characters', message: null });
    }
    
    // Sanitize inputs
    const cleanUsername = sanitizeInput(username);
    const cleanEmail = sanitizeInput(email);
    
    // SECURE: Hash password with bcrypt
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    // SECURE: Parameterized query
    const query = 'INSERT INTO users (username, email, password, profile) VALUES (?, ?, ?, ?)';
    
    db.run(query, [cleanUsername, cleanEmail, hashedPassword, 'New User'], function(err) {
        if (err) {
            logger.error('Signup error', { error: err.message });
            return res.render('signup', { error: 'Username or email already exists', message: null });
        }
        
        logger.info('New user registered', { username: cleanUsername });
        res.render('signup', { error: null, message: 'Account created successfully!' });
    });
});

// SECURE: Profile update with input sanitization
app.post('/profile', authenticateToken, (req, res) => {
    const { profile } = req.body;
    
    // SECURE: Sanitize profile input to prevent XSS
    const cleanProfile = sanitizeInput(profile);
    
    const query = 'UPDATE users SET profile = ? WHERE id = ?';
    
    db.run(query, [cleanProfile, req.user.userId], (err) => {
        if (err) {
            logger.error('Profile update error', { error: err.message });
        } else {
            logger.info('Profile updated', { userId: req.user.userId });
        }
        res.redirect('/profile');
    });
});

// SECURE: Search with parameterized query
app.get('/search', authenticateToken, (req, res) => {
    const { q } = req.query;
    
    if (!q || !validator.isAlphanumeric(q.replace(/\\s/g, ''))) {
        return res.json({ users: [] });
    }
    
    // SECURE: Parameterized query
    const query = 'SELECT id, username, email, profile FROM users WHERE username LIKE ? OR email LIKE ?';
    const searchTerm = `%${sanitizeInput(q)}%`;
    
    db.all(query, [searchTerm, searchTerm], (err, rows) => {
        if (err) {
            logger.error('Search error', { error: err.message });
            return res.json({ error: 'Search failed' });
        }
        
        // Remove sensitive data
        const safeRows = rows.map(row => ({
            id: row.id,
            username: row.username,
            email: row.email,
            profile: row.profile
        }));
        
        res.json({ users: safeRows });
    });
});

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.user });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/signup', (req, res) => {
    res.render('signup', { error: null, message: null });
});

app.get('/profile', authenticateToken, (req, res) => {
    const query = 'SELECT * FROM users WHERE id = ?';
    db.get(query, [req.user.userId], (err, row) => {
        if (err || !row) {
            return res.redirect('/login');
        }
        res.render('profile', { user: row });
    });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

app.listen(PORT, () => {
    logger.info(`Secure server running on http://localhost:${PORT}`);
});