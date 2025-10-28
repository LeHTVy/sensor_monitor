#!/usr/bin/env python3
"""
Security Middleware for Capture Server
Provides authentication, authorization, and IP whitelisting
"""

import os
import jwt
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
import ipaddress

class CaptureSecurity:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security middleware with Flask app"""
        self.app = app
        
        # Generate API key if not exists
        if not os.getenv('CAPTURE_API_KEY'):
            api_key = self.generate_api_key()
            app.config['CAPTURE_API_KEY'] = api_key
            print(f"Generated API Key: {api_key}")
        else:
            app.config['CAPTURE_API_KEY'] = os.getenv('CAPTURE_API_KEY')
        
        # Generate JWT secret if not exists
        if not os.getenv('JWT_SECRET'):
            jwt_secret = self.generate_jwt_secret()
            app.config['JWT_SECRET'] = jwt_secret
            print(f"Generated JWT Secret: {jwt_secret}")
        else:
            app.config['JWT_SECRET'] = os.getenv('JWT_SECRET')
        
        # Admin network (default: local networks)
        admin_networks = os.getenv('ADMIN_NETWORKS', '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8')
        app.config['ADMIN_NETWORKS'] = [net.strip() for net in admin_networks.split(',')]
        
        print(f"Security middleware initialized")
        print(f"Admin networks: {app.config['ADMIN_NETWORKS']}")
    
    def generate_api_key(self):
        """Generate a secure API key"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def generate_jwt_secret(self):
        """Generate a secure JWT secret"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def is_admin_ip(self, ip):
        """Check if IP is in admin network"""
        try:
            client_ip = ipaddress.ip_address(ip)
            for network_str in self.app.config['ADMIN_NETWORKS']:
                network = ipaddress.ip_network(network_str, strict=False)
                if client_ip in network:
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        return False
    
    def verify_api_key(self, api_key):
        """Verify API key"""
        return api_key == self.app.config['CAPTURE_API_KEY']
    
    def generate_jwt_token(self, user_id='admin', expires_hours=24):
        """Generate JWT token for admin access"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expires_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.app.config['JWT_SECRET'], algorithm='HS256')
    
    def verify_jwt_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.app.config['JWT_SECRET'], algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

def api_key_required(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Get security instance from current app
        security = getattr(current_app, 'security', None)
        if not security or not security.verify_api_key(api_key):
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin access (JWT or API key)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for JWT token first
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            security = getattr(current_app, 'security', None)
            if security:
                payload = security.verify_jwt_token(token)
                if payload:
                    return f(*args, **kwargs)
        
        # Fallback to API key
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if api_key:
            security = getattr(current_app, 'security', None)
            if security and security.verify_api_key(api_key):
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Admin access required'}), 403
    return decorated_function

def ip_whitelist_required(f):
    """Decorator to require IP whitelist (admin networks)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        
        # Check if IP is in admin networks
        security = getattr(current_app, 'security', None)
        if not security or not security.is_admin_ip(client_ip):
            return jsonify({'error': 'Access denied from this IP'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def create_security_middleware(app):
    """Factory function to create security middleware"""
    security = CaptureSecurity(app)
    app.security = security
    return security