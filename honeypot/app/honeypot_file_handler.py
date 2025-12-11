#!/usr/bin/env python3
"""
Honeypot File Upload Handler
Integrates with malware_collector to capture uploaded files
Runs static analysis locally and sends results to capture server
"""

import os
import json
import uuid
from datetime import datetime
from kafka import KafkaProducer
from werkzeug.utils import secure_filename
import logging

try:
    from utils.static_analyzer import SimpleStaticAnalyzer
    analyzer = SimpleStaticAnalyzer()
except Exception as e:
    print(f"⚠️ Could not load static analyzer: {e}")
    analyzer = None

logger = logging.getLogger(__name__)


class HoneypotFileHandler:
    """
    Handles file uploads in the honeypot
    Saves files and sends events to Kafka for malware analysis
    """

    def __init__(self, upload_dir='uploads', kafka_servers=None):
        self.upload_dir = upload_dir
        os.makedirs(self.upload_dir, exist_ok=True)
        
        # Get Kafka servers from env or parameter
        if kafka_servers is None:
            kafka_env = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
            kafka_servers = kafka_env.split(',')
        
        # Initialize Kafka producer
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=kafka_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            logger.info(f"✅ Kafka producer initialized: {kafka_servers}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Kafka producer: {e}")
            self.producer = None

    def handle_file_upload(self, uploaded_file, request_info: dict) -> dict:
        """
        Handle file upload from attacker
        
        Args:
            uploaded_file: Flask FileStorage object
            request_info: HTTP request metadata (IP, headers, etc.)
            
        Returns:
            Dict with file info and status
        """
        try:
            # Generate unique filename
            original_filename = secure_filename(uploaded_file.filename)
            unique_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            
            # Save file to honeypot uploads directory
            file_path = os.path.join(self.upload_dir, f"{unique_id}_{original_filename}")
            uploaded_file.save(file_path)
            
            file_size = os.path.getsize(file_path)
            
            logger.info(f"📁 File uploaded: {original_filename} ({file_size:,} bytes)")
            logger.info(f"   Source IP: {request_info.get('source_ip')}")
            logger.info(f"   Saved to: {file_path}")
            
            # Run static analysis on the file (on honeypot)
            analysis_result = None
            if analyzer:
                try:
                    analysis_result = analyzer.analyze(file_path)
                    logger.info(f"🔬 Analysis complete: Risk {analysis_result.get('risk_level', 'UNKNOWN')}")
                except Exception as e:
                    logger.warning(f"⚠️ Analysis error: {e}")
            
            # Prepare malware sample event for Kafka (with analysis results)
            malware_event = {
                'event_type': 'file_upload',
                'timestamp': timestamp,
                'file_id': unique_id,
                'original_filename': original_filename,
                'file_size': file_size,
                'source_ip': request_info.get('source_ip', 'unknown'),
                'attack_id': request_info.get('attack_id'),
                # Include analysis results from honeypot
                'static_analysis': analysis_result,
                'risk_score': analysis_result.get('risk_score', 0) if analysis_result else 0,
                'risk_level': analysis_result.get('risk_level', 'UNKNOWN') if analysis_result else 'UNKNOWN',
                'hashes': analysis_result.get('hashes', {}) if analysis_result else {},
                'file_type': analysis_result.get('file_type', {}) if analysis_result else {},
                'context': {
                    'user_agent': request_info.get('user_agent'),
                    'referer': request_info.get('referer'),
                    'upload_field': request_info.get('upload_field'),
                    'form_data': request_info.get('form_data', {}),
                    'honeypot_endpoint': request_info.get('endpoint')
                }
            }
            
            # Send to Kafka
            if self.producer:
                self.producer.send('malware-samples', value=malware_event)
                self.producer.flush()
                logger.info(f"✅ Malware analysis sent to Kafka: {unique_id} - Risk: {malware_event.get('risk_level')}")
            
            return {
                'success': True,
                'file_id': unique_id,
                'filename': original_filename,
                'size': file_size,
                'path': file_path,
                'risk_level': malware_event.get('risk_level'),
                'risk_score': malware_event.get('risk_score'),
                'hashes': malware_event.get('hashes'),
                'file_type': malware_event.get('file_type'),
                'static_analysis': analysis_result
            }
            
        except Exception as e:
            logger.error(f"❌ Error handling file upload: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e)
            }

    def detect_payload_in_request(self, request_data: dict) -> bool:
        """
        Detect suspicious payloads in POST/GET data
        
        Args:
            request_data: Dict with args, form_data, path, etc.
            
        Returns:
            True if suspicious payload detected
        """
        suspicious_patterns = [
            # Code injection
            'eval(', 'exec(', 'system(', 'shell_exec(',
            'base64_decode', 'gzinflate', 'str_rot13',
            
            # Command injection
            '&&', '||', ';rm ', ';wget ', ';curl ',
            
            # SQL injection
            "' OR '1'='1", "' OR 1=1--", 'UNION SELECT',
            
            # XSS
            '<script>', 'javascript:', 'onerror=',
            
            # Path traversal
            '../', '..\\', '/etc/passwd', 'C:\\Windows',
            
            # Webshell indicators
            '<?php', '<%', 'WSH', 'WScript.Shell',
            
            # Encoding tricks
            '%00', '\x00', '\\u0000'
        ]
        
        # Combine all request data
        combined_data = str(request_data.get('args', '')) + \
                       str(request_data.get('form_data', '')) + \
                       str(request_data.get('path', ''))
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern.lower() in combined_data.lower():
                logger.warning(f"🚨 Suspicious payload detected: {pattern}")
                return True
        
        return False

    def extract_and_send_payload(self, payload_data: str, request_info: dict):
        """
        Extract malicious payload and send to malware analysis
        
        Args:
            payload_data: The suspicious payload string
            request_info: HTTP request metadata
        """
        try:
            malware_event = {
                'event_type': 'payload_detected',
                'timestamp': datetime.now().isoformat(),
                'payload_data': payload_data,
                'payload_type': 'injection_attempt',
                'source_ip': request_info.get('source_ip', 'unknown'),
                'attack_id': request_info.get('attack_id'),
                'context': {
                    'path': request_info.get('path'),
                    'method': request_info.get('method'),
                    'user_agent': request_info.get('user_agent'),
                    'detection_reason': 'suspicious_pattern'
                }
            }
            
            if self.producer:
                self.producer.send('malware-samples', value=malware_event)
                self.producer.flush()
                logger.info(f"✅ Payload extraction event sent to Kafka")
            
        except Exception as e:
            logger.error(f"❌ Error extracting payload: {e}")


# Example usage in Flask honeypot app
def integrate_with_flask_app(app):
    """
    Example integration with Flask honeypot application
    
    Add this to your honeypot app.py:
    
    from honeypot_file_handler import HoneypotFileHandler, integrate_with_flask_app
    
    # Initialize file handler
    file_handler = HoneypotFileHandler(
        upload_dir='/app/uploads',
        kafka_servers=['kafka:9092']
    )
    
    # In your file upload route:
    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' in request.files:
            uploaded_file = request.files['file']
            
            request_info = {
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'referer': request.headers.get('Referer'),
                'upload_field': 'file',
                'form_data': request.form.to_dict(),
                'endpoint': request.path,
                'attack_id': generate_attack_log_id()  # Your attack logging function
            }
            
            result = file_handler.handle_file_upload(uploaded_file, request_info)
            
            if result['success']:
                # Return fake success to attacker
                return jsonify({'status': 'success', 'message': 'File uploaded'})
            else:
                return jsonify({'status': 'error', 'message': 'Upload failed'}), 500
    
    # In any route that accepts POST data:
    @app.route('/api/execute', methods=['POST'])
    def execute_command():
        request_info = {
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'path': request.path,
            'method': request.method,
            'args': request.args.to_dict(),
            'form_data': request.form.to_dict(),
            'attack_id': generate_attack_log_id()
        }
        
        # Check for payload injection
        if file_handler.detect_payload_in_request(request_info):
            # Extract and analyze the payload
            payload_str = str(request.form) + str(request.args)
            file_handler.extract_and_send_payload(payload_str, request_info)
            
            # Log the attack...
            # Still return fake response to attacker
        
        return jsonify({'status': 'executed'})
    """
    pass


if __name__ == "__main__":
    # Test the file handler
    handler = HoneypotFileHandler(upload_dir='test_uploads')
    
    print("✅ Honeypot File Handler initialized")
    print(f"   Upload directory: {handler.upload_dir}")
    print(f"   Kafka producer: {'Connected' if handler.producer else 'Not connected'}")
