# Security Policy

## Secure REST API Security Features

### Implemented Security Measures

✅ **TLS/HTTPS Encryption**
- Self-signed certificates for development
- Production: Use CA-signed certificates from Let's Encrypt or your CA
- Enforced HTTPS-only communication
- Strong cipher suites (TLS 1.2+)

✅ **JWT Authentication**
- Stateless token-based authentication
- HS256 signing algorithm
- Token expiration (configurable, default 24 hours)
- Secure token storage (client-side)

✅ **Password Security**
- Bcrypt hashing with salts
- Never store plaintext passwords
- Password hashing with Werkzeug

✅ **Rate Limiting**
- Prevent brute force attacks
- Default: 200 requests/day, 50 requests/hour
- Per-endpoint limiting available

✅ **CORS Protection**
- Configurable allowed origins
- Prevents unauthorized cross-origin requests

✅ **Input Validation**
- Marshmallow schema validation
- Sanitization of all user inputs
- SQL injection prevention (via ORM)

✅ **Error Handling**
- Secure error messages (no sensitive data leaks)
- Proper HTTP status codes
- Comprehensive logging

✅ **Database Security**
- PostgreSQL with encrypted connections
- Parameterized queries (SQLAlchemy ORM)
- Connection pooling

### Vulnerability Disclosure

If you discover a security vulnerability, please:

1. **DO NOT** open a public GitHub issue
2. Email security details to: [your-security-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Security Best Practices for Production

#### 1. Certificate Management
```bash
# Generate proper certificates from CA
certbot certonly --standalone -d yourdomain.com
# Place in certs/ directory
```

#### 2. Environment Variables
```bash
# Never commit .env to version control
SECRET_KEY=<strong-random-key>
JWT_SECRET_KEY=<strong-random-key>
DATABASE_URL=postgresql://user:pass@host/db
FLASK_ENV=production
```

#### 3. Database Hardening
- Use strong passwords
- Enable SSL for database connections
- Restrict network access
- Regular backups
- Implement connection timeouts

#### 4. Application Security
- Keep dependencies updated
- Run security scanners: `bandit`, `safety`
- Use HTTPS only
- Implement request logging
- Monitor failed auth attempts

#### 5. Deployment
- Use non-root Docker user
- Minimal Docker images (Alpine Linux)
- Resource limits (CPU, memory)
- Health checks
- Restart policies

#### 6. Monitoring
- Log all security events
- Monitor error rates
- Track authentication attempts
- Set up alerts for suspicious activity

### Dependencies Security

Keep dependencies updated:
```bash
# Check for vulnerabilities
safety check
bandit -r src/
flake8 app.py

# Update dependencies
pip install --upgrade -r requirements.txt
```

### Testing

Run tests before deployment:
```bash
pytest tests/ -v
pytest tests/ --cov=src
```

### Regular Security Audits

- Monthly: Review logs and alerts
- Quarterly: Security assessment
- Annually: Full penetration test

## Compliance

This API follows:
- OWASP Top 10 security practices
- CWE/SANS Top 25 recommendations
- Best practices for REST API security

## Support

For security questions, contact the development team.
