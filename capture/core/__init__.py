"""Core infrastructure modules - Kafka, Security"""
from .kafka_consumer import CaptureKafkaConsumer
from .security_middleware import CaptureSecurity, admin_required, api_key_required, ip_whitelist_required
