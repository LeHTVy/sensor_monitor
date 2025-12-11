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
from honeypot_file_handler import HoneypotFileHandler

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

# Initialize file handler for malware sample collection
try:
    file_handler = HoneypotFileHandler(
        upload_dir='/app/uploads',
        kafka_servers=[os.getenv('KAFKA_BOOTSTRAP_SERVERS', '10.8.0.1:9093')]
    )
    print("✅ File handler initialized for malware sample collection")
except Exception as e:
    print(f"⚠️ Warning: Failed to initialize file handler: {e}")
    file_handler = None

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
# IDS Engine removed - now handled by capture server
# Cleanup worker no longer needed
def ensure_kafka_worker_started():
    """Ensure Kafka worker thread is started (thread-safe, called from request handler)"""
    global kafka_thread, _worker_started_flag
    if not _worker_started_flag:
        with _worker_started:
            if not _worker_started_flag:
                kafka_thread = threading.Thread(target=kafka_worker, daemon=True)
                kafka_thread.start()
                _worker_started_flag = True
                print(f"✅ Kafka background worker started in process {os.getpid()}")

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
        content_type = request.headers.get('Content-Type', '')
        is_file_upload = 'multipart/form-data' in content_type
        
        raw_body = ""
        if not is_file_upload:
            try:
                if request.content_length and request.content_length < 10240:  # 10KB limit
                    raw_body = request.get_data(as_text=True)
            except:
                pass
        
        # Now capture form data 
        form_data = {}
        try:
            form_data = dict(request.form) if request.form else {}
        except:
            pass
        
        # Capture JSON body
        json_body = {}
        try:
            if request.is_json:
                json_body = request.get_json(silent=True) or {}
        except:
            pass
        
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
            'form_data': form_data,
            'json_body': json_body,
            'raw_body': raw_body,
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
    # IDS removed - stats only for honeypot activity
    return jsonify({
        'honeypot_version': '2.0',
        'uptime': '...',
        'total_requests': 'N/A'
    }), 200

# IDS API endpoints removed - IDS functionality moved to capture server


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
            sent_to_analyzer = False
            file_id = None
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Use file handler to save and send to malware analyzer
            if file_handler:
                request_info = {
                    'source_ip': request.headers.get('X-Real-IP', request.remote_addr),
                    'user_agent': request.headers.get('User-Agent', ''),
                    'referer': request.headers.get('Referer', ''),
                    'upload_field': 'file',
                    'form_data': dict(request.form),
                    'endpoint': request.path
                }
                
                result = file_handler.handle_file_upload(file, request_info)
                sent_to_analyzer = result.get('success', False)
                file_id = result.get('file_id', '')
                filepath = result.get('path', filepath)
            else:
                # Fallback: just save file locally
                file.save(filepath)
            
            # Log file upload as attack
            attack_data = {
                'type': 'file_upload',
                'method': 'POST',
                'path': '/upload',
                'filename': filename,
                'filepath': filepath,
                'file_id': file_id,
                'ip': request.headers.get('X-Real-IP', request.remote_addr),
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.now().isoformat(),
                'sent_to_malware_analyzer': sent_to_analyzer,
                'form_data': dict(request.form),
                'files': [filename],
                'log_category': 'attack'
            }
            
            logger.log_attack(attack_data)
            
            # Send to Kafka for capture server
            try:
                kafka_queue.put_nowait(('attack', attack_data))
            except:
                pass
            
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
            'method': 'POST',
            'path': '/console',
            'command': command,
            'ip': request.headers.get('X-Real-IP', request.remote_addr),
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat(),
            'form_data': {'command': command},
            'log_category': 'attack'
        }
        logger.log_attack(attack_data)
        
        # Send to Kafka
        try:
            kafka_queue.put_nowait(('attack', attack_data))
        except:
            pass

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

@app.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
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
        'method': request.method,
        'path': '/api/users',
        'endpoint': '/api/users',
        'search': search,
        'query': query,
        'ip': request.headers.get('X-Real-IP', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.now().isoformat(),
        'form_data': dict(request.form) if request.form else {},
        'json_body': request.get_json(silent=True) or {},
        'log_category': 'attack'
    }
    
    logger.log_attack(attack_data)
    
    # Send to Kafka
    try:
        kafka_queue.put_nowait(('attack', attack_data))
    except:
        pass

    # Return fake response based on method
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    elif request.method in ['POST', 'PUT']:
        return jsonify({'success': True, 'message': 'User saved successfully', 'id': 999})
    return jsonify(FAKE_DATABASES['users'])


@app.route('/api/products', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_products():
    """API endpoint for product data"""
    attack_data = {
        'type': 'api_access',
        'method': request.method,
        'path': '/api/products',
        'ip': request.headers.get('X-Real-IP', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.now().isoformat(),
        'form_data': dict(request.form) if request.form else {},
        'json_body': request.get_json(silent=True) or {},
        'args': dict(request.args),
        'log_category': 'attack'
    }
    logger.log_attack(attack_data)
    try:
        kafka_queue.put_nowait(('attack', attack_data))
    except:
        pass
    
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': 'Product deleted'})
    elif request.method in ['POST', 'PUT']:
        return jsonify({'success': True, 'message': 'Product saved', 'id': 999})
    return jsonify(FAKE_DATABASES['products'])


@app.route('/api/orders', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_orders():
    """API endpoint for order data"""
    attack_data = {
        'type': 'api_access',
        'method': request.method,
        'path': '/api/orders',
        'ip': request.headers.get('X-Real-IP', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.now().isoformat(),
        'form_data': dict(request.form) if request.form else {},
        'json_body': request.get_json(silent=True) or {},
        'args': dict(request.args),
        'log_category': 'attack'
    }
    logger.log_attack(attack_data)
    try:
        kafka_queue.put_nowait(('attack', attack_data))
    except:
        pass
    
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': 'Order deleted'})
    elif request.method in ['POST', 'PUT']:
        return jsonify({'success': True, 'message': 'Order created', 'id': 999})
    return jsonify(FAKE_DATABASES['orders'])

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
