#!/usr/bin/env python3
"""
API Keys Manager - Elasticsearch-based API Key Management
Provides role-based API keys for enterprise threat intelligence access
"""

import os
import secrets
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from elasticsearch import Elasticsearch
import logging

logger = logging.getLogger(__name__)


class APIKeyRole:
    """API Key roles with permissions"""
    ADMIN = "admin"          # Full access - create keys, manage users, all API
    SOC = "soc"              # SOC analyst - read threats, export reports
    SIEM = "siem"            # SIEM integration - read-only threats/logs
    READONLY = "readonly"    # Basic read-only access
    
    # Permission mapping
    PERMISSIONS = {
        ADMIN: ["read", "write", "export", "manage_keys", "admin"],
        SOC: ["read", "export"],
        SIEM: ["read"],
        READONLY: ["read"]
    }
    
    @classmethod
    def get_permissions(cls, role: str) -> List[str]:
        return cls.PERMISSIONS.get(role, [])
    
    @classmethod
    def has_permission(cls, role: str, permission: str) -> bool:
        return permission in cls.get_permissions(role)


class APIKeysManager:
    """
    Manages API keys stored in Elasticsearch
    
    Usage:
        manager = APIKeysManager()
        key_info = manager.create_key("Firewall Integration", "siem")
        # Returns: {"api_key": "xxx", "key_id": "xxx", ...}
        
        # Validate key
        key_data = manager.validate_key("xxx")
        if key_data and APIKeyRole.has_permission(key_data['role'], 'read'):
            # Allow access
    """
    
    INDEX_NAME = "api-keys"
    
    def __init__(self, es_url: str = None):
        """Initialize API Keys Manager"""
        self.es_url = es_url or os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200')
        self.es = None
        self._connect()
        self._ensure_index()
        
        # Master API key from env (always works, for bootstrap)
        self.master_key = os.getenv('CAPTURE_API_KEY', '')
    
    def _connect(self) -> bool:
        """Connect to Elasticsearch"""
        try:
            self.es = Elasticsearch(self.es_url)
            if self.es.ping():
                logger.info(f"✅ API Keys Manager connected to Elasticsearch")
                return True
        except Exception as e:
            logger.error(f"❌ Failed to connect to Elasticsearch: {e}")
        return False
    
    def _ensure_index(self):
        """Create API keys index if not exists"""
        if not self.es:
            return
            
        try:
            if not self.es.indices.exists(index=self.INDEX_NAME):
                mapping = {
                    "mappings": {
                        "properties": {
                            "key_id": {"type": "keyword"},
                            "key_hash": {"type": "keyword"},  # Store hash, not plain key
                            "name": {"type": "text"},
                            "description": {"type": "text"},
                            "role": {"type": "keyword"},
                            "created_by": {"type": "keyword"},
                            "created_at": {"type": "date"},
                            "last_used": {"type": "date"},
                            "use_count": {"type": "integer"},
                            "is_active": {"type": "boolean"},
                            "expires_at": {"type": "date"}
                        }
                    }
                }
                self.es.indices.create(index=self.INDEX_NAME, body=mapping)
                logger.info(f"✅ Created index: {self.INDEX_NAME}")
        except Exception as e:
            logger.error(f"❌ Failed to create index: {e}")
    
    def _hash_key(self, api_key: str) -> str:
        """Hash API key for secure storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def _generate_key(self) -> str:
        """Generate a secure API key"""
        return secrets.token_hex(32)
    
    def create_key(self, name: str, role: str, description: str = "", 
                   created_by: str = "admin", expires_days: int = None) -> Dict:
        """
        Create a new API key
        
        Args:
            name: Key name (e.g., "Firewall Integration")
            role: One of admin, soc, siem, readonly
            description: Optional description
            created_by: Who created this key
            expires_days: Optional expiration in days
            
        Returns:
            {"api_key": "xxx", "key_id": "xxx", "name": "...", "role": "..."}
        """
        if not self.es:
            raise Exception("Elasticsearch not connected")
        
        if role not in [APIKeyRole.ADMIN, APIKeyRole.SOC, APIKeyRole.SIEM, APIKeyRole.READONLY]:
            raise ValueError(f"Invalid role: {role}. Must be one of: admin, soc, siem, readonly")
        
        # Generate key
        api_key = self._generate_key()
        key_id = secrets.token_hex(8)
        key_hash = self._hash_key(api_key)
        
        now = datetime.utcnow()
        expires_at = None
        if expires_days:
            from datetime import timedelta
            expires_at = (now + timedelta(days=expires_days)).isoformat()
        
        # Store in Elasticsearch
        doc = {
            "key_id": key_id,
            "key_hash": key_hash,
            "name": name,
            "description": description,
            "role": role,
            "created_by": created_by,
            "created_at": now.isoformat(),
            "last_used": None,
            "use_count": 0,
            "is_active": True,
            "expires_at": expires_at
        }
        
        self.es.index(index=self.INDEX_NAME, id=key_id, body=doc, refresh=True)
        logger.info(f"✅ Created API key: {name} (role: {role})")
        
        return {
            "api_key": api_key,  # Only returned once!
            "key_id": key_id,
            "name": name,
            "role": role,
            "permissions": APIKeyRole.get_permissions(role),
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "message": "⚠️ Save this API key now! It won't be shown again."
        }
    
    def validate_key(self, api_key: str) -> Optional[Dict]:
        """
        Validate an API key and return key info
        
        Args:
            api_key: The API key to validate
            
        Returns:
            Key info dict if valid, None if invalid
        """
        # Check master key first (from env)
        if self.master_key and api_key == self.master_key:
            return {
                "key_id": "master",
                "name": "Master Key",
                "role": APIKeyRole.ADMIN,
                "permissions": APIKeyRole.get_permissions(APIKeyRole.ADMIN),
                "is_master": True
            }
        
        if not self.es:
            return None
        
        try:
            key_hash = self._hash_key(api_key)
            
            # Search for key by hash
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"key_hash": key_hash}},
                            {"term": {"is_active": True}}
                        ]
                    }
                }
            }
            
            res = self.es.search(index=self.INDEX_NAME, body=query)
            
            if res['hits']['total']['value'] == 0:
                return None
            
            hit = res['hits']['hits'][0]
            key_data = hit['_source']
            
            # Check expiration
            if key_data.get('expires_at'):
                expires = datetime.fromisoformat(key_data['expires_at'].replace('Z', '+00:00'))
                if datetime.utcnow() > expires.replace(tzinfo=None):
                    logger.warning(f"API key expired: {key_data['name']}")
                    return None
            
            # Update usage stats
            self.es.update(
                index=self.INDEX_NAME,
                id=key_data['key_id'],
                body={
                    "doc": {
                        "last_used": datetime.utcnow().isoformat(),
                        "use_count": key_data.get('use_count', 0) + 1
                    }
                }
            )
            
            return {
                "key_id": key_data['key_id'],
                "name": key_data['name'],
                "role": key_data['role'],
                "permissions": APIKeyRole.get_permissions(key_data['role']),
                "created_by": key_data.get('created_by'),
                "use_count": key_data.get('use_count', 0) + 1
            }
            
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None
    
    def list_keys(self) -> List[Dict]:
        """List all API keys (without revealing the actual keys)"""
        if not self.es:
            return []
        
        try:
            query = {
                "size": 100,
                "sort": [{"created_at": {"order": "desc"}}],
                "query": {"match_all": {}},
                "_source": ["key_id", "name", "description", "role", "created_by", 
                           "created_at", "last_used", "use_count", "is_active", "expires_at"]
            }
            
            res = self.es.search(index=self.INDEX_NAME, body=query)
            
            keys = []
            for hit in res['hits']['hits']:
                key = hit['_source']
                key['permissions'] = APIKeyRole.get_permissions(key['role'])
                keys.append(key)
            
            return keys
            
        except Exception as e:
            logger.error(f"Error listing API keys: {e}")
            return []
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke (deactivate) an API key"""
        if not self.es:
            return False
        
        try:
            self.es.update(
                index=self.INDEX_NAME,
                id=key_id,
                body={"doc": {"is_active": False}},
                refresh=True
            )
            logger.info(f"✅ Revoked API key: {key_id}")
            return True
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return False
    
    def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key"""
        if not self.es:
            return False
        
        try:
            self.es.delete(index=self.INDEX_NAME, id=key_id, refresh=True)
            logger.info(f"✅ Deleted API key: {key_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting API key: {e}")
            return False
    
    def get_key_stats(self) -> Dict:
        """Get API key statistics"""
        if not self.es:
            return {}
        
        try:
            query = {
                "size": 0,
                "aggs": {
                    "total_keys": {"value_count": {"field": "key_id"}},
                    "active_keys": {"filter": {"term": {"is_active": True}}},
                    "by_role": {"terms": {"field": "role"}},
                    "total_usage": {"sum": {"field": "use_count"}}
                }
            }
            
            res = self.es.search(index=self.INDEX_NAME, body=query)
            aggs = res.get('aggregations', {})
            
            return {
                "total_keys": aggs.get('total_keys', {}).get('value', 0),
                "active_keys": aggs.get('active_keys', {}).get('doc_count', 0),
                "by_role": {b['key']: b['doc_count'] for b in aggs.get('by_role', {}).get('buckets', [])},
                "total_api_calls": int(aggs.get('total_usage', {}).get('value', 0))
            }
        except Exception as e:
            logger.error(f"Error getting key stats: {e}")
            return {}


# Global instance
_api_keys_manager = None


def get_api_keys_manager() -> APIKeysManager:
    """Get or create global API Keys Manager instance"""
    global _api_keys_manager
    if _api_keys_manager is None:
        _api_keys_manager = APIKeysManager()
    return _api_keys_manager
