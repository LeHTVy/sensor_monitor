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
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename
from utils.logger import HoneypotLogger
from utils.sender import LogSender
from utils.kafka_producer import HoneypotKafkaProducer
from utils.mysql_ai_console import MySQLAIConsole

app = Flask(__name__)
app.secret_key = 'honeypot_secret_key_12345'

# Initialize logging, sender and Kafka producer (with error handling)
try:
    logger = HoneypotLogger()
except Exception as e:
    print(f"❌ Failed to initialize logger: {e}")
    raise

# Initialize LogSender (optional, can continue without it)
try:
    sender = LogSender()
except Exception as e:
    print(f"⚠️ Failed to initialize LogSender: {e}, continuing without it")
    sender = None

# Initialize Kafka producer - MANDATORY: app will fail to start if Kafka is not available
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

# Configuration
UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'php', 'sh', 'py', 'exe'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directory
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
def log_request():
    """Log every request before processing"""
    try:
        # Get detailed log data from logger
        log_entry = logger.log_request(request)
        
        # Store request info for after_request hook
        request._log_entry = log_entry
        
        # Prepare log data for Kafka
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
            'attack_tool': log_entry.get('attack_tool', 'unknown'),
            'attack_tool_info': log_entry.get('attack_tool_info', {}),  # Include enhanced detection info
            'attack_technique': log_entry.get('attack_technique', []),
            'geoip': log_entry.get('geoip', {}),
            'os_info': log_entry.get('os_info', {}),
            'log_category': log_entry.get('log_category', 'unknown')
        }
        
        # Send to Kafka based on log category - MANDATORY: must succeed
        try:
            category = log_entry.get('log_category')
            success = False
            
            if category == 'attack':
                success = kafka_producer.send_attack_log(log_data)
                if success:
                    print(f"✅ Sent attack log to Kafka: {log_entry.get('attack_tool', 'unknown')}")
            elif category == 'traffic':
                success = kafka_producer.send_traffic_log(log_data)
                if success:
                    print(f"✅ Sent traffic log to Kafka: {request.method} {request.path}")
            elif category == 'honeypot':
                success = kafka_producer.send_browser_log(log_data)
                if success:
                    print(f"✅ Sent browser log to Kafka: {log_entry.get('attack_tool', 'browser')}")
            else:
                success = kafka_producer.send_error_log(log_data)
                if success:
                    print(f"✅ Sent error log to Kafka: {category}")
            
            if not success:
                print(f"⚠️ Warning: Failed to send {category} log to Kafka, but continuing...")
                
        except Exception as kafka_error:
            # Log error but don't crash - retry will happen on next request
            print(f"❌ Kafka error sending log: {str(kafka_error)}")
            # Re-raise if it's a connection error (producer dead)
            if "Connection" in str(kafka_error) or "Broker" in str(kafka_error):
                print(f"❌ CRITICAL: Kafka connection lost, application may need restart")
        
        # Note: Logs are sent via Kafka only (no HTTP duplicate)
        # Kafka → Collector → Elasticsearch → Frontend
        
    except Exception as e:
        print(f"Error logging request: {str(e)}")
        # Send error to Kafka (mandatory)
        try:
            kafka_producer.send_error_log({
                'type': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'ip': request.headers.get('X-Real-IP', request.remote_addr) if 'request' in locals() else 'unknown'
            })
        except Exception as kafka_err:
            print(f"❌ Failed to send error log to Kafka: {str(kafka_err)}")

@app.after_request
def update_response_context(response):
    """Update tool processor context with response code"""
    try:
        if hasattr(request, '_log_entry'):
            real_ip = request.headers.get('X-Real-IP', request.remote_addr)
            logger.tool_processor.update_response_code(real_ip, response.status_code)
    except Exception as e:
        print(f"⚠️ Error updating response context: {e}")
    return response

@app.route('/')
def index():
    """Redirect to login page"""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Vulnerable login page with SQL injection"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Intentionally vulnerable SQL query for SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        # Log the attack attempt
        attack_data = {
            'type': 'sql_injection_attempt',
            'username': username,
            'password': password,
            'query': query,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.log_attack(attack_data)
        sender.send_log(attack_data)
        
        # Simulate database response (always fail to keep them trying)
        flash('Invalid credentials. Please try again.', 'error')
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Fake admin dashboard"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', databases=FAKE_DATABASES)

@app.route('/database/<db_name>')
def view_database(db_name):
    """View fake database tables"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if db_name in FAKE_DATABASES:
        return render_template('database.html', 
                             db_name=db_name, 
                             data=FAKE_DATABASES[db_name])
    else:
        flash('Database not found', 'error')
        return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Vulnerable file upload"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
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
            sender.send_log(attack_data)
            
            flash(f'File {filename} uploaded successfully!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type', 'error')
    
    return render_template('upload.html')

@app.route('/console', methods=['GET', 'POST'])
def console():
    """AI-driven MySQL-like console (no real command execution)"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Initialize console per session
    if 'mysql_console' not in session:
        session['mysql_console'] = True
    console_engine = app.config.setdefault('mysql_console_engine', MySQLAIConsole())

    output = ""
    if request.method == 'POST':
        command = request.form.get('command', '')

        # Log interaction as activity (not actual command execution)
        attack_data = {
            'type': 'console_interaction',
            'command': command,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        logger.log_attack(attack_data)
        sender.send_log(attack_data)

        # Use stateful simulator
        session_id = session.get('username', request.remote_addr or 'anon')
        output = console_engine.handle_command(command, session_id)

    # Initial banner like MySQL client
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
def api_users():
    """API endpoint for user data (vulnerable to injection)"""
    search = request.args.get('search', '')
    
    # Vulnerable query construction
    if search:
        query = f"SELECT * FROM users WHERE username LIKE '%{search}%'"
    else:
        query = "SELECT * FROM users"
    
    # Log API access
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
    sender.send_log(attack_data)
    
    # Return fake data
    return jsonify(FAKE_DATABASES['users'])

@app.route('/admin')
def admin_panel():
    """Hidden admin panel"""
    return render_template('admin.html', databases=FAKE_DATABASES)

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Simulate successful login for demonstration
@app.route('/auth', methods=['POST'])
def auth():
    """Fake authentication endpoint"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Always "succeed" to keep them engaged
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
    sender.send_log(attack_data)
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
