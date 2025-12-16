# Secure REST API - Usage Guide

## Overview

This is a production-ready REST API with TLS/HTTPS encryption and JWT (JSON Web Token) authentication.

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate TLS Certificates

```bash
python generate_certs.py
```

This creates `certs/server.crt` and `certs/server.key` for HTTPS.

### 3. Set Environment Variables (Optional)

```bash
export SECRET_KEY="your-secure-secret-key"
export JWT_EXPIRATION_HOURS=24
export CERT_FILE="certs/server.crt"
export KEY_FILE="certs/server.key"
export DEBUG=False
```

### 4. Run the Server

```bash
python app.py
```

Server runs on `https://0.0.0.0:5000`

## API Endpoints

### Health Check (No Auth)

```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-12-17T12:00:00.000000",
  "service": "secure-rest-api"
}
```

### Login (Get JWT Token)

```bash
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin-password-123"
}
```

Response:
```json
{
  "message": "Login successful",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 86400
}
```

**Default Credentials:**
- Username: `admin`, Password: `admin-password-123`
- Username: `user`, Password: `user-password-456`

### Get Secure Data (Requires JWT)

```bash
GET /api/secure/data
Authorization: Bearer <JWT_TOKEN>
```

Response:
```json
{
  "message": "Secure data retrieved successfully",
  "user": "admin",
  "data": {
    "id": 1,
    "name": "Sensitive Information",
    "timestamp": "2024-12-17T12:00:00.000000"
  }
}
```

### Create Data (Requires JWT)

```bash
POST /api/secure/data
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "name": "New Data",
  "value": "123"
}
```

### Get User Profile (Requires JWT)

```bash
GET /api/user/profile
Authorization: Bearer <JWT_TOKEN>
```

Response:
```json
{
  "username": "admin",
  "token_issued_at": "2024-12-17T12:00:00.000000",
  "token_expires_at": "2024-12-18T12:00:00.000000"
}
```

## Example Workflow

### Using cURL

```bash
# 1. Check health
curl -k https://localhost:5000/health

# 2. Login and get token
TOKEN=$(curl -k -X POST https://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin-password-123"}' | \
  jq -r '.token')

# 3. Use token to access protected endpoint
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:5000/api/secure/data
```

### Using Python

```python
import requests
import json

BASE_URL = "https://localhost:5000"

# Disable SSL verification for self-signed certs
requests.packages.urllib3.disable_warnings()

# 1. Login
response = requests.post(
    f"{BASE_URL}/auth/login",
    json={"username": "admin", "password": "admin-password-123"},
    verify=False
)
token = response.json()["token"]

# 2. Use token
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(
    f"{BASE_URL}/api/secure/data",
    headers=headers,
    verify=False
)
print(response.json())
```

## Security Features

✓ **TLS/HTTPS Encryption** - All traffic encrypted
✓ **JWT Authentication** - Token-based auth
✓ **Password Hashing** - Using Werkzeug
✓ **Token Expiration** - Automatic token expiry
✓ **Error Handling** - Secure error messages
✓ **Self-Signed Certificates** - For development/testing

## Security Best Practices

1. **Change Default Credentials** - Update VALID_CREDENTIALS in app.py
2. **Use Strong Secret Key** - Set SECRET_KEY environment variable
3. **Replace Self-Signed Certs** - Use CA-signed certificates in production
4. **Enable DEBUG=False** - Never run with debug=True in production
5. **Use HTTPS Only** - Enforce HTTPS in production
6. **Implement Rate Limiting** - Add rate limiting to prevent brute force
7. **Add CORS Policy** - Configure CORS appropriately
8. **Log Security Events** - Monitor authentication failures

## Troubleshooting

### SSL Certificate Errors

For development, disable SSL verification in clients:
- Python: `verify=False` in requests
- cURL: `-k` or `--insecure` flag
- Browser: Accept the security exception

### Token Expired

Get a new token by logging in again.

### Invalid Token Format

Ensure header format is: `Authorization: Bearer <token>`

## Production Deployment

### Using Gunicorn

```bash
gunicorn --certfile=certs/server.crt --keyfile=certs/server.key app:app
```

### Docker

Create a Dockerfile for containerized deployment.

## License

MIT License
