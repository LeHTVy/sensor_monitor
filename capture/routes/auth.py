"""
Authentication Routes - Login and API Keys Management
With enhanced logging for security monitoring
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import os
import secrets
import logging

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Track failed login attempts (in-memory, resets on restart)
failed_login_attempts = {}
LOCK_THRESHOLD = 5
LOCK_DURATION_MINUTES = 15

# Security logger for audit trail
security_logger = logging.getLogger('security')


def get_client_ip():
    """Get client IP from request"""
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def log_auth_event(event_type: str, username: str = None, success: bool = True, details: str = None):
    """Log authentication events for security monitoring"""
    client_ip = get_client_ip()
    timestamp = datetime.now().isoformat()
    
    log_entry = f"[AUTH] {event_type} | IP: {client_ip}"
    if username:
        log_entry += f" | User: {username}"
    log_entry += f" | Success: {success}"
    if details:
        log_entry += f" | {details}"
    
    if success:
        security_logger.info(log_entry)
    else:
        security_logger.warning(log_entry)


def log_api_key_event(event_type: str, key_name: str = None, key_id: str = None, role: str = None, details: str = None):
    """Log API key events for monitoring"""
    client_ip = get_client_ip()
    timestamp = datetime.now().isoformat()
    
    log_entry = f"[API_KEY] {event_type} | IP: {client_ip}"
    if key_name:
        log_entry += f" | Name: {key_name}"
    if key_id:
        log_entry += f" | KeyID: {key_id}"
    if role:
        log_entry += f" | Role: {role}"
    if details:
        log_entry += f" | {details}"
    
    security_logger.info(log_entry)


@auth_bp.route('/login', methods=['POST'])
def login():
    """Login endpoint to get API key with account lock protection"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    client_ip = get_client_ip()
    
    # Check if account is locked
    if username in failed_login_attempts:
        attempts, lock_time = failed_login_attempts[username]
        if attempts >= LOCK_THRESHOLD and lock_time:
            if datetime.now() < lock_time:
                minutes_left = int((lock_time - datetime.now()).total_seconds() / 60) + 1
                log_auth_event("LOGIN_BLOCKED", username, False, f"Account locked, {minutes_left} min remaining")
                return jsonify({
                    'success': False,
                    'message': f'Account locked after {LOCK_THRESHOLD} attempts. Try again in {minutes_left} minutes.'
                }), 403
            else:
                # Lock expired, reset
                del failed_login_attempts[username]
    
    # Get credentials from environment (with secure defaults that MUST be changed)
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    # Security check: Require ADMIN_PASSWORD to be set in environment
    if not admin_password:
        logging.warning("⚠️ ADMIN_PASSWORD not set in environment! Using insecure default.")
        admin_password = 'changeme'  # Force users to set proper password
    
    if username == admin_username and password == admin_password:
        # Clear failed attempts on success
        if username in failed_login_attempts:
            del failed_login_attempts[username]
            
        api_key = os.getenv('CAPTURE_API_KEY')
        if not api_key:
            logging.warning("⚠️ CAPTURE_API_KEY not set! Generating temporary key.")
            api_key = secrets.token_hex(32)
        
        security = current_app.security
        jwt_token = security.generate_jwt_token('admin')
        
        # Log successful login
        log_auth_event("LOGIN_SUCCESS", username, True, f"JWT issued, expires in 7 days")
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'jwt_token': jwt_token,
            'expires_in_days': 7,
            'message': 'Login successful'
        })
    
    # Track failed attempt
    if username not in failed_login_attempts:
        failed_login_attempts[username] = (1, None)
        remaining = LOCK_THRESHOLD - 1
    else:
        attempts, _ = failed_login_attempts[username]
        attempts += 1
        lock_time = datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES) if attempts >= LOCK_THRESHOLD else None
        failed_login_attempts[username] = (attempts, lock_time)
        remaining = max(0, LOCK_THRESHOLD - attempts)
    
    # Log failed login
    log_auth_event("LOGIN_FAILED", username, False, f"{remaining} attempts remaining")
    
    return jsonify({
        'success': False,
        'message': 'Invalid username or password',
        'attempts_remaining': remaining
    }), 401


# =============================================================================
# API KEYS MANAGEMENT ENDPOINTS
# =============================================================================

def get_api_keys_manager():
    """Get API keys manager if available"""
    try:
        from services.api_keys_manager import get_api_keys_manager as _get_manager
        return _get_manager()
    except ImportError:
        return None

def is_api_keys_available():
    """Check if API keys manager is available"""
    try:
        from services.api_keys_manager import get_api_keys_manager
        return True
    except ImportError:
        return False


@auth_bp.route('/keys', methods=['POST'])
def create_api_key():
    """Create a new API key"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    data = request.get_json()
    name = data.get('name', '').strip()
    role = data.get('role', '').lower()
    description = data.get('description', '')
    expires_days = data.get('expires_days')
    
    if not name:
        return jsonify({'error': 'Key name is required'}), 400
    
    if role not in ['admin', 'soc', 'siem', 'readonly']:
        return jsonify({
            'error': 'Invalid role',
            'valid_roles': ['admin', 'soc', 'siem', 'readonly']
        }), 400
    
    try:
        manager = get_api_keys_manager()
        result = manager.create_key(
            name=name,
            role=role,
            description=description,
            created_by='admin',
            expires_days=expires_days
        )
        
        # Log API key creation
        log_api_key_event("KEY_CREATED", key_name=name, key_id=result.get('key_id'), role=role,
                         details=f"Expires: {expires_days or 'never'} days")
        
        return jsonify(result), 201
    except Exception as e:
        logging.error(f"API key creation error: {e}")
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/keys', methods=['GET'])
def list_api_keys():
    """List all API keys (without revealing actual keys)"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    try:
        manager = get_api_keys_manager()
        keys = manager.list_keys()
        stats = manager.get_key_stats()
        
        # Log API key listing
        log_api_key_event("KEYS_LISTED", details=f"Total: {len(keys)} keys")
        
        return jsonify({
            'keys': keys,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/keys/<key_id>', methods=['GET'])
def get_api_key(key_id):
    """Get details of a specific API key"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    try:
        manager = get_api_keys_manager()
        keys = manager.list_keys()
        
        for key in keys:
            if key['key_id'] == key_id:
                log_api_key_event("KEY_VIEWED", key_id=key_id, key_name=key.get('name'))
                return jsonify(key)
        
        return jsonify({'error': 'Key not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/keys/<key_id>/revoke', methods=['POST'])
def revoke_api_key(key_id):
    """Revoke (deactivate) an API key"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    try:
        manager = get_api_keys_manager()
        success = manager.revoke_key(key_id)
        
        if success:
            # Log API key revocation
            log_api_key_event("KEY_REVOKED", key_id=key_id, details="Key deactivated")
            return jsonify({
                'success': True,
                'message': f'API key {key_id} has been revoked'
            })
        else:
            return jsonify({'error': 'Failed to revoke key'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/keys/<key_id>', methods=['DELETE'])
def delete_api_key(key_id):
    """Permanently delete an API key"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    try:
        manager = get_api_keys_manager()
        success = manager.delete_key(key_id)
        
        if success:
            # Log API key deletion
            log_api_key_event("KEY_DELETED", key_id=key_id, details="Permanently removed")
            return jsonify({
                'success': True,
                'message': f'API key {key_id} has been deleted'
            })
        else:
            return jsonify({'error': 'Failed to delete key'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/keys/stats', methods=['GET'])
def api_keys_stats():
    """Get API key usage statistics"""
    if not is_api_keys_available():
        return jsonify({'error': 'API Keys Manager not available'}), 503
    
    try:
        manager = get_api_keys_manager()
        stats = manager.get_key_stats()
        
        log_api_key_event("STATS_VIEWED", details=f"Total API calls: {stats.get('total_api_calls', 0)}")
        
        return jsonify({
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
