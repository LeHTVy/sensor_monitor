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

app = Flask(__name__)
app.secret_key = 'honeypot_secret_key_12345'

# Initialize logging and sender
logger = HoneypotLogger()
sender = LogSender()

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
        logger.log_request(request)
        # Also send to capture server immediately
        sender.send_log({
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
            'files': list(request.files.keys()) if request.files else []
        })
    except Exception as e:
        print(f"Error logging request: {str(e)}")

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
    """Vulnerable command execution console"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    output = ""
    if request.method == 'POST':
        command = request.form.get('command', '')
        
        # Log command execution attempt
        attack_data = {
            'type': 'command_injection',
            'command': command,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.log_attack(attack_data)
        sender.send_log(attack_data)
        
        try:
            # Intentionally vulnerable command execution
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            output = f"$ {command}\n{result.stdout}\n{result.stderr}"
        except subprocess.TimeoutExpired:
            output = f"$ {command}\nCommand timed out"
        except Exception as e:
            output = f"$ {command}\nError: {str(e)}"
    
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
