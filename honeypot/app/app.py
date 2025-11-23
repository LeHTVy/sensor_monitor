#!/usr/bin/env python3
"""
Honeypot Flask Application
Fake admin database interface with intentional vulnerabilities
"""

import os
import subprocess
import sqlite3
import json
import hashlib
import threading
import queue
import time
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from werkzeug.utils import secure_filename
from utils.logger import HoneypotLogger
from utils.kafka_producer import HoneypotKafkaProducer

app = Flask(__name__)
app.secret_key = 'honeypot_secret_key_12345'
_worker_started = threading.Lock()
_worker_started_flag = False

# Initialize logging, sender and Kafka producer (with error handling)
try:
    logger = HoneypotLogger()
except Exception as e:
    print(f"❌ Failed to initialize logger: {e}")
    raise

try:
    print("🔗 Initializing Kafka producer (REQUIRED)...")
    kafka_producer = HoneypotKafkaProducer()
    if kafka_producer.producer is None:
        raise RuntimeError("Kafka producer initialized but producer object is None")
    print("✅ Kafka producer initialized successfully - honeypot is ready")
except Exception as e:
    error_msg = f"""
    ❌ CRITICAL ERROR: Failed to initialize Kafka producer!
    
    Kafka is REQUIRED for honeypot operation. The application cannot start without Kafka connection.
    
    Error details: {str(e)}
    
    Please ensure:
    1. Kafka is running and accessible at: {os.getenv('KAFKA_BOOTSTRAP_SERVERS', '172.232.224.160:9093')}
    2. Network connectivity from honeypot to Kafka server
    3. Kafka broker is listening on the correct port
    4. WireGuard VPN is configured correctly (if using VPN)
    
    Application will exit now.
    """
    print(error_msg)
    raise SystemExit(1) from e

kafka_queue = queue.Queue(maxsize=1000)

def kafka_worker():
    """Background worker to send logs to Kafka without blocking requests"""
    print(f"🔄 Kafka worker thread started, waiting for logs...")
    processed = 0
    while True:
        try:
            log_task = kafka_queue.get(timeout=1)
            if log_task is None:
                break
            category, log_data = log_task
            processed += 1
            print(f"📥 Kafka worker: Processing {category} log #{processed} from queue (queue size: {kafka_queue.qsize()})")
            try:
                if category == 'attack':
                    result = kafka_producer.send_attack_log(log_data)
                    if result:
                        print(f"✅ Worker: Successfully sent {category} log to Kafka")
                    else:
                        print(f"⚠️ Worker: Failed to send {category} log to Kafka")
                elif category == 'traffic':
                    result = kafka_producer.send_traffic_log(log_data)
                    if result:
                        print(f"✅ Worker: Successfully sent {category} log to Kafka")
                    else:
                        print(f"⚠️ Worker: Failed to send {category} log to Kafka")
                elif category == 'honeypot':
                    result = kafka_producer.send_browser_log(log_data)
                    if result:
                        print(f"✅ Worker: Successfully sent {category} log to Kafka")
                    else:
                        print(f"⚠️ Worker: Failed to send {category} log to Kafka")
                else:
                    result = kafka_producer.send_error_log(log_data)
                    if result:
                        print(f"✅ Worker: Successfully sent {category} log to Kafka")
                    else:
                        print(f"⚠️ Worker: Failed to send {category} log to Kafka")
            except Exception as e:
                print(f"❌ Error in kafka worker sending log: {str(e)}")
                import traceback
                print(traceback.format_exc())
            finally:
                kafka_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"❌ Kafka worker error: {str(e)}")
            import time
            time.sleep(0.1)

kafka_thread = None
cleanup_thread = None

def ids_cleanup_worker():
    """Background worker to cleanup IDS engine expired blocks and old contexts"""
    print("🧹 IDS cleanup worker started")
    while True:
        try:
            time.sleep(300)  # Run every 5 minutes
            logger.ids_engine.cleanup_expired_blocks()
            logger.ids_engine.cleanup_old_contexts(max_age_hours=24)
        except Exception as e:
            print(f"❌ IDS cleanup worker error: {e}")

def ensure_kafka_worker_started():
    """Ensure Kafka worker thread is started (thread-safe, called from request handler)"""
    global kafka_thread, cleanup_thread, _worker_started_flag
    if not _worker_started_flag:
        with _worker_started:
            if not _worker_started_flag:
                kafka_thread = threading.Thread(target=kafka_worker, daemon=True)
                kafka_thread.start()
                cleanup_thread = threading.Thread(target=ids_cleanup_worker, daemon=True)
                cleanup_thread.start()
                _worker_started_flag = True
                print(f"✅ Kafka background worker started in process {os.getpid()}")
                print(f"✅ IDS cleanup worker started in process {os.getpid()}")

try:
    ensure_kafka_worker_started()
except Exception as e:
    print(f"⚠️ Could not start Kafka worker: {e}")

# Configuration
UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'php', 'sh', 'py', 'exe'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Fake database data
FAKE_DATABASES = {
    'users': [
        {'id': 1, 'username': 'admin', 'email': 'admin@company.com', 'role': 'Administrator'},
        {'id': 2, 'username': 'john', 'email': 'john@company.com', 'role': 'User'},
        {'id': 3, 'username': 'sarah', 'email': 'sarah@company.com', 'role': 'Manager'},
    ],
    'products': [
        {'id': 1, 'name': 'Product A', 'price': 100, 'stock': 50},
        {'id': 2, 'name': 'Product B', 'price': 200, 'stock': 30},
        {'id': 3, 'name': 'Product C', 'price': 150, 'stock': 75},
    ],
    'orders': [
        {'id': 1, 'user_id': 1, 'product_id': 1, 'quantity': 2, 'total': 200},
        {'id': 2, 'user_id': 2, 'product_id': 2, 'quantity': 1, 'total': 200},
    ]
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_request
def check_authentication():
    """Check authentication for all routes except public ones"""
    if request.path in PUBLIC_ROUTES or request.path.startswith('/static'):
        return
    
    if not session.get('logged_in'):
        return redirect(url_for('login'))

@app.before_request
def log_request():
    """Log every request before processing"""
    if request.path in SKIP_LOG_ROUTES:
        return
    
    ensure_kafka_worker_started()
    
    try:
        log_entry = logger.log_request(request)
        
        request._log_entry = log_entry
        
        # Send raw log data to Kafka (enrichment happens on capture server)
        log_data = {
            'type': 'request',
            'method': request.method,
            'url': request.url,
            'path': request.path,
            'ip': request.headers.get('X-Real-IP', request.remote_addr),
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat(),
            'headers': dict(request.headers),
            'args': dict(request.args),
            'form_data': dict(request.form) if request.form else {},
            'files': list(request.files.keys()) if request.files else [],
            'log_category': log_entry.get('log_category', 'traffic')
        }
        
        try:
            category = log_entry.get('log_category', 'unknown')
            try:
                kafka_queue.put_nowait((category, log_data))
                print(f"📤 Queued {category} log to Kafka worker (queue size: {kafka_queue.qsize()})")
            except queue.Full:
                print(f"⚠️ Kafka queue full ({kafka_queue.qsize()} items), dropping log: {category}")
        except Exception as kafka_error:
            print(f"❌ Kafka queue error: {str(kafka_error)}")
            import traceback
            print(traceback.format_exc())
        
    except Exception as e:
        print(f"Error logging request: {str(e)}")
        try:
            error_log = {
                'type': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'ip': request.headers.get('X-Real-IP', request.remote_addr) if 'request' in locals() else 'unknown'
            }
            kafka_queue.put_nowait(('error', error_log))
        except:
            pass

@app.after_request
def update_response_context(response):
    """Lightweight response handler (no heavy processing)"""
    # Just return response - no tool processor in lightweight mode
    return response

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

PUBLIC_ROUTES = ['/login', '/auth', '/health', '/static', '/favicon.ico']

SKIP_LOG_ROUTES = ['/favicon.ico', '/health']

@app.route('/health')
def health():
    """Health check endpoint"""
    ids_stats = logger.ids_engine.get_statistics()
    return jsonify({
        'status': 'healthy',
        'kafka': 'connected' if kafka_producer and kafka_producer.producer else 'disconnected',
        'queue_size': kafka_queue.qsize(),
        'ids': ids_stats,
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/ids/stats')
@login_required
def ids_stats():
    """IDS statistics endpoint"""
    stats = logger.ids_engine.get_statistics()
    return jsonify(stats), 200

@app.route('/api/ids/ip/<ip>')
@login_required
def ids_ip_info(ip):
    """Get IDS information for specific IP"""
    ip_stats = logger.ids_engine.get_ip_stats(ip)
    return jsonify(ip_stats), 200

@app.route('/api/ids/blocked')
@login_required
def ids_blocked_ips():
    """Get list of blocked IPs"""
    blocked = []
    for ip, block_info in logger.ids_engine.blocked_ips.items():
        if not block_info.is_expired():
            blocked.append({
                'ip': ip,
                'reason': block_info.reason.value,
                'blocked_at': block_info.blocked_at.isoformat(),
                'blocked_until': block_info.blocked_until.isoformat(),
                'block_count': block_info.block_count
            })
    return jsonify({'blocked_ips': blocked, 'count': len(blocked)}), 200

@app.route('/api/ids/whitelist', methods=['GET', 'POST'])
@login_required
def ids_whitelist():
    """Manage whitelist"""
    if request.method == 'POST':
        ip = request.json.get('ip')
        if ip:
            logger.ids_engine.add_to_whitelist(ip)
            return jsonify({'status': 'success', 'message': f'IP {ip} added to whitelist'}), 200
        return jsonify({'status': 'error', 'message': 'IP required'}), 400
    else:
        return jsonify({'whitelist': list(logger.ids_engine.whitelist)}), 200

@app.route('/api/ids/blacklist', methods=['GET', 'POST'])
@login_required
def ids_blacklist():
    """Manage blacklist"""
    if request.method == 'POST':
        ip = request.json.get('ip')
        if ip:
            logger.ids_engine.add_to_blacklist(ip)
            return jsonify({'status': 'success', 'message': f'IP {ip} added to blacklist'}), 200
        return jsonify({'status': 'error', 'message': 'IP required'}), 400
    else:
        return jsonify({'blacklist': list(logger.ids_engine.blacklist)}), 200

@app.route('/favicon.ico')
def favicon():
    """Serve favicon.ico from assets folder"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        assets_dir = os.path.join(app_dir, 'templates', 'assets')
        favicon_path = os.path.join(assets_dir, 'databaseadmin.ico')
        
        if os.path.exists(favicon_path):
            return send_from_directory(assets_dir, 'databaseadmin.ico', mimetype='image/x-icon')
        else:
            print(f"⚠️ Favicon not found at: {favicon_path}")
            return '', 204
    except Exception as e:
        print(f"⚠️ Error serving favicon: {e}")
        return '', 204

@app.route('/')
def index():
    """Redirect to login page"""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - redirect to dashboard if already logged in"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return redirect(url_for('auth'))
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Fake admin dashboard"""
    return render_template('dashboard.html', databases=FAKE_DATABASES)

@app.route('/database/<db_name>')
@login_required
def view_database(db_name):
    """View fake database tables"""
    
    if db_name in FAKE_DATABASES:
        return render_template('database.html', 
                             db_name=db_name, 
                             data=FAKE_DATABASES[db_name])
    else:
        flash('Database not found', 'error')
        return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Vulnerable file upload"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Log file upload attempt
            attack_data = {
                'type': 'file_upload',
                'filename': filename,
                'filepath': filepath,
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            logger.log_attack(attack_data)
            
            flash(f'File {filename} uploaded successfully!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type', 'error')
    
    return render_template('upload.html')

@app.route('/console', methods=['GET', 'POST'])
@login_required
def console():
    """Simple SQL console simulator (no real command execution)"""
    output = ""
    if request.method == 'POST':
        command = request.form.get('command', '')

        attack_data = {
            'type': 'console_interaction',
            'command': command,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        logger.log_attack(attack_data)

        # Simple responses for common commands
        cmd_upper = command.strip().upper()
        if cmd_upper.startswith('SHOW TABLES'):
            output = (
                "+-----------------+\n"
                "| Tables_in_admin |\n"
                "+-----------------+\n"
                "| users           |\n"
                "| products        |\n"
                "| orders          |\n"
                "+-----------------+\n"
                "3 rows in set (0.00 sec)\n\nmysql> "
            )
        elif cmd_upper.startswith('SELECT'):
            output = (
                "+----+----------+---------------------+---------+\n"
                "| id | username | email               | role    |\n"
                "+----+----------+---------------------+---------+\n"
                "|  1 | admin    | admin@company.com   | Admin   |\n"
                "|  2 | john     | john@company.com    | User    |\n"
                "+----+----------+---------------------+---------+\n"
                "2 rows in set (0.01 sec)\n\nmysql> "
            )
        else:
            output = f"Query OK, 1 row affected (0.00 sec)\n\nmysql> "

    if not output:
        output = (
            "Welcome to the MySQL monitor.  Commands end with ; or \n.\n"
            f"Your MySQL connection id is {abs(hash(session.get('username', 'guest'))) % 10000}\n"
            "Server version: 8.0.25 MySQL Community Server - GPL\n\n"
            "Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n"
            "mysql> "
        )

    return render_template('console.html', output=output)

@app.route('/api/users')
@login_required
def api_users():
    """API endpoint for user data (vulnerable to injection)"""
    search = request.args.get('search', '')
    
    if search:
        query = f"SELECT * FROM users WHERE username LIKE '%{search}%'"
    else:
        query = "SELECT * FROM users"
    
    attack_data = {
        'type': 'api_access',
        'endpoint': '/api/users',
        'search': search,
        'query': query,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.now().isoformat()
    }
    
    logger.log_attack(attack_data)

    return jsonify(FAKE_DATABASES['users'])

@app.route('/admin')
@login_required
def admin_panel():
    """Hidden admin panel"""
    return render_template('admin.html', databases=FAKE_DATABASES)

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Authentication credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'DeepGreen2025'

@app.route('/auth', methods=['POST'])
def auth():
    """Authentication endpoint - requires correct credentials"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Check credentials
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        # Valid credentials
        session['logged_in'] = True
        session['username'] = username
        
        attack_data = {
            'type': 'authentication_attempt',
            'username': username,
            'password': password,
            'success': True,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }

        logger.log_attack(attack_data)

        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # Invalid credentials - log failed attempt
        attack_data = {
            'type': 'authentication_attempt',
            'username': username,
            'password': password,
            'success': False,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }

        logger.log_attack(attack_data)

        flash('Invalid username or password. Please try again.', 'error')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
