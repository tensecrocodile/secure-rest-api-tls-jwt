#!/usr/bin/env python3
"""
Secure REST API with TLS/HTTPS and JWT Authentication
Production-ready Flask API with security best practices
"""

import os
import ssl
import json
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Tuple

from flask import Flask, request, jsonify
from jwt import encode, decode, InvalidTokenError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_EXPIRATION_HOURS'] = int(os.environ.get('JWT_EXPIRATION_HOURS', '24'))
app.config['CERT_FILE'] = os.environ.get('CERT_FILE', 'certs/server.crt')
app.config['KEY_FILE'] = os.environ.get('KEY_FILE', 'certs/server.key')

# Hardcoded credentials (replace with database in production)
VALID_CREDENTIALS = {
    'admin': generate_password_hash('admin-password-123'),
    'user': generate_password_hash('user-password-456')
}


def jwt_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            payload = decode(token, app.config['SECRET_KEY'], 
                            algorithms=[app.config['JWT_ALGORITHM']])
            request.user = payload
        except InvalidTokenError as e:
            return jsonify({'error': f'Token is invalid: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint (no auth required)"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'secure-rest-api'
    }), 200


@app.route('/auth/login', methods=['POST'])
def login():
    """Login endpoint - exchange credentials for JWT token"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Verify credentials
    if username not in VALID_CREDENTIALS:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not check_password_hash(VALID_CREDENTIALS[username], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate JWT token
    payload = {
        'username': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    }
    
    token = encode(payload, app.config['SECRET_KEY'], 
                   algorithm=app.config['JWT_ALGORITHM'])
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'expires_in': app.config['JWT_EXPIRATION_HOURS'] * 3600  # seconds
    }), 200


@app.route('/api/secure/data', methods=['GET'])
@jwt_required
def get_secure_data():
    """Protected endpoint - requires valid JWT"""
    return jsonify({
        'message': 'Secure data retrieved successfully',
        'user': request.user.get('username'),
        'data': {
            'id': 1,
            'name': 'Sensitive Information',
            'timestamp': datetime.utcnow().isoformat()
        }
    }), 200


@app.route('/api/secure/data', methods=['POST'])
@jwt_required
def create_secure_data():
    """Protected POST endpoint"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    
    return jsonify({
        'message': 'Data created successfully',
        'user': request.user.get('username'),
        'data_received': data,
        'timestamp': datetime.utcnow().isoformat()
    }), 201


@app.route('/api/user/profile', methods=['GET'])
@jwt_required
def get_user_profile():
    """Get current user profile"""
    return jsonify({
        'username': request.user.get('username'),
        'token_issued_at': request.user.get('iat'),
        'token_expires_at': request.user.get('exp')
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


def run_secure_server(host='0.0.0.0', port=5000, debug=False):
    """Run Flask app with TLS/SSL support"""
    # Create SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Load certificate and key
    try:
        ssl_context.load_cert_chain(
            certfile=app.config['CERT_FILE'],
            keyfile=app.config['KEY_FILE']
        )
        print(f"[*] Loaded TLS certificate from {app.config['CERT_FILE']}")
        print(f"[*] Loaded TLS key from {app.config['KEY_FILE']}")
    except FileNotFoundError:
        print("[!] SSL certificate or key not found!")
        print("[!] Generate them with: python generate_certs.py")
        print("[!] Running without TLS (development only)")
        ssl_context = None
    
    print(f"[*] Starting Secure REST API on {host}:{port}")
    print(f"[*] JWT Algorithm: {app.config['JWT_ALGORITHM']}")
    print(f"[*] JWT Expiration: {app.config['JWT_EXPIRATION_HOURS']} hours")
    print("[*] Default credentials: admin/admin-password-123, user/user-password-456")
    
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)


if __name__ == '__main__':
    run_secure_server(debug=os.environ.get('DEBUG', 'False').lower() == 'true')
