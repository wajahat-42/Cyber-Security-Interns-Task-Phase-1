# User Management System - Cybersecurity Internship Project

## Overview
This project is a mock User Management System created for cybersecurity training purposes. It contains intentional vulnerabilities for educational use in learning about web application security.

## Project Structure

### Files
- `server.js` - Vulnerable version with security issues
- `server-secure.js` - Secured version with all fixes implemented
- `package.json` - Project dependencies
- `views/` - EJS templates for the application

### Vulnerabilities Present (server.js)
1. **SQL Injection** - Direct string concatenation in SQL queries
2. **Cross-Site Scripting (XSS)** - Unescaped output in templates
3. **Weak Password Storage** - Plaintext passwords
4. **Security Misconfigurations** - Weak session secrets, missing headers

## Security Implementations (server-secure.js)

### Week 2 Security Measures
1. **Input Validation** - Using `validator` library
2. **Password Hashing** - Using `bcrypt` with salt rounds
3. **JWT Authentication** - Token-based authentication
4. **Security Headers** - Using `helmet.js`
5. **Logging** - Using `winston` for audit trails

## Installation

```bash
npm install
```

## Running the Application

### Vulnerable Version
```bash
npm start
# or
node server.js
```

### Secure Version
```bash
node server-secure.js
```

## Testing

### SQL Injection Test
```bash
curl -X POST http://localhost:3000/login \
  -d "username=' OR '1'='1&password=' OR '1'='1"
```

### XSS Test
Update profile with:
```html
<script>alert('XSS')</script>
```

### Search Function
```bash
curl "http://localhost:3000/search?q=admin"
```

## Security Checklist

- [x] Input validation implemented
- [x] Password hashing with bcrypt
- [x] JWT token authentication
- [x] Security headers with Helmet.js
- [x] Parameterized queries
- [x] XSS prevention
- [x] Comprehensive logging
- [x] Error handling without information disclosure

## Technologies Used

- Node.js
- Express.js
- SQLite3
- EJS (templating)
- bcrypt (password hashing)
- jsonwebtoken (JWT)
- helmet.js (security headers)
- validator (input validation)
- winston (logging)

## License

This project is for educational purposes only.