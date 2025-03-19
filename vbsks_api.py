#!/usr/bin/env python3
"""
VBSKS API - REST API for Vector-Based Secure Key Storage

This module provides a Flask-based REST API for integrating VBSKS into enterprise applications.
"""

import os
import json
import base64
import logging
import secrets
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from functools import wraps

from vbsks_easy import VBSKSEasy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vbsks_api')

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# API keys for authentication (in a real production system, use a proper auth system)
api_keys = {}
if 'VBSKS_API_KEY' in os.environ:
    api_keys[os.environ['VBSKS_API_KEY']] = 'admin'

# If no API key is set, generate a random one for demo purposes
if not api_keys:
    demo_key = secrets.token_hex(32)
    api_keys[demo_key] = 'demo'
    print(f"\n=== DEMO API KEY (save this for API access) ===\n{demo_key}\n=========================================\n")

# VBSKS instance
vbsks_instance = None

def get_vbsks():
    """Get or initialize the VBSKS instance"""
    global vbsks_instance
    if vbsks_instance is None:
        db_folder = os.environ.get('VBSKS_DB_FOLDER', 'vbsks_data')
        vbsks_instance = VBSKSEasy(db_folder=db_folder)
    return vbsks_instance

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in api_keys:
            return jsonify({'error': 'Unauthorized - Valid API key required'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/status', methods=['GET'])
def api_status():
    """API status endpoint"""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/keys', methods=['GET'])
@require_api_key
def list_keys():
    """List all keys in the database"""
    try:
        vbsks = get_vbsks()
        result = vbsks.list_keys()
        return jsonify(result)
    except Exception as e:
        logger.exception("Error listing keys")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['GET'])
@require_api_key
def get_key(key_id):
    """Get information about a specific key (not including the key material)"""
    try:
        vbsks = get_vbsks()
        result = vbsks.list_keys()
        if result['status'] != 'success':
            return jsonify(result), 500
        
        keys = result['keys']
        if key_id not in keys:
            return jsonify({'status': 'error', 'error': 'Key not found'}), 404
        
        return jsonify({
            'status': 'success',
            'key_id': key_id,
            'key_info': keys[key_id]
        })
    except Exception as e:
        logger.exception(f"Error getting key {key_id}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/keys/<key_id>/retrieve', methods=['POST'])
@require_api_key
def retrieve_key(key_id):
    """Retrieve a key from the database"""
    try:
        data = request.get_json()
        if not data or 'master_password' not in data:
            return jsonify({'status': 'error', 'error': 'Master password required'}), 400
        
        master_password = data['master_password']
        
        vbsks = get_vbsks()
        result = vbsks.retrieve_key(key_id, master_password)
        
        if result['status'] != 'success':
            if 'error' in result and 'not found' in result['error'].lower():
                return jsonify(result), 404
            return jsonify(result), 400
        
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error retrieving key {key_id}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/keys', methods=['POST'])
@require_api_key
def store_key():
    """Store a key in the database"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'error': 'No JSON data provided'}), 400
        
        required_fields = ['key_id', 'master_password']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'error': f'Missing required field: {field}'}), 400
        
        key_id = data['key_id']
        master_password = data['master_password']
        
        # Optional fields
        key_data = data.get('key_data')
        metadata = data.get('metadata', {})
        
        # If key_data is base64 encoded, decode it
        if key_data and isinstance(key_data, str) and data.get('is_base64', False):
            try:
                key_data = base64.b64decode(key_data)
            except Exception as e:
                return jsonify({'status': 'error', 'error': f'Invalid base64 data: {str(e)}'}), 400
        
        vbsks = get_vbsks()
        result = vbsks.store_key(key_id, master_password, key_data, metadata)
        
        if result['status'] != 'success':
            return jsonify(result), 400
        
        return jsonify(result), 201
    except Exception as e:
        logger.exception("Error storing key")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['DELETE'])
@require_api_key
def delete_key(key_id):
    """Delete a key from the database"""
    try:
        vbsks = get_vbsks()
        result = vbsks.delete_key(key_id)
        
        if result['status'] != 'success':
            if 'error' in result and 'not found' in result['error'].lower():
                return jsonify(result), 404
            return jsonify(result), 400
        
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error deleting key {key_id}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/backup', methods=['POST'])
@require_api_key
def create_backup():
    """Create a secure backup of the database"""
    try:
        data = request.get_json()
        if not data or 'backup_password' not in data:
            return jsonify({'status': 'error', 'error': 'Backup password required'}), 400
        
        backup_password = data['backup_password']
        
        vbsks = get_vbsks()
        result = vbsks.backup_database(backup_password)
        
        if result['status'] != 'success':
            return jsonify(result), 400
        
        return jsonify(result)
    except Exception as e:
        logger.exception("Error creating backup")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/restore', methods=['POST'])
@require_api_key
def restore_backup():
    """Restore database from a backup"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'error': 'No JSON data provided'}), 400
        
        required_fields = ['backup_file', 'backup_password']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'error': f'Missing required field: {field}'}), 400
        
        backup_file = data['backup_file']
        backup_password = data['backup_password']
        key_map_backup = data.get('key_map_backup')
        
        # Validate files exist
        if not os.path.exists(backup_file):
            return jsonify({'status': 'error', 'error': f'Backup file not found: {backup_file}'}), 404
        
        if key_map_backup and not os.path.exists(key_map_backup):
            return jsonify({'status': 'error', 'error': f'Key map backup file not found: {key_map_backup}'}), 404
        
        vbsks = get_vbsks()
        result = vbsks.restore_database(backup_file, backup_password, key_map_backup)
        
        if result['status'] != 'success':
            return jsonify(result), 400
        
        return jsonify(result)
    except Exception as e:
        logger.exception("Error restoring backup")
        return jsonify({'status': 'error', 'error': str(e)}), 500

def main():
    """Main entry point for the API server"""
    # Get configuration from environment
    host = os.environ.get('VBSKS_API_HOST', '127.0.0.1')
    port = int(os.environ.get('VBSKS_API_PORT', 5000))
    debug = os.environ.get('VBSKS_API_DEBUG', 'false').lower() == 'true'
    
    # Load environment variables from .env file if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    
    # Initialize VBSKS
    get_vbsks()
    
    # Run the app
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    main() 