#!/usr/bin/env python3
"""
VBSKS Easy - Consumer-friendly interface for Vector-Based Secure Key Storage

This module provides simplified functions for using VBSKS without needing to
understand the underlying vector database mechanics.
"""

import os
import base64
import json
import logging
from typing import Dict, Any, Optional, Union, Tuple
from pathlib import Path

# Import core VBSKS components
from vector_db import VectorDatabase
from key_manager import QuantumResistantKeyManager
from secure_storage import SecureStorage
from map_manager import MapManager
from reconfiguration_controller import ReconfigurationController

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vbsks_easy')

class VBSKSEasy:
    """
    Consumer-friendly interface for VBSKS.
    
    This class simplifies key storage and retrieval operations for end users
    without requiring understanding of vector databases or cryptography details.
    """
    
    def __init__(
        self,
        db_folder: str = "vbsks_data",
        auto_reconfigure: bool = True,
        reconfiguration_interval: int = 86400,  # Default: once per day
        dimensions: int = 100,
        db_size: int = 10000,
        key_length: int = 8
    ):
        """
        Initialize the VBSKS Easy interface.
        
        Args:
            db_folder: Directory to store database files
            auto_reconfigure: Whether to enable automatic key reconfiguration
            reconfiguration_interval: Time between reconfigurations (seconds)
            dimensions: Dimensions per vector
            db_size: Size of the vector database
            key_length: Number of vectors in each key
        """
        self.db_folder = Path(db_folder)
        self.db_folder.mkdir(parents=True, exist_ok=True)
        
        # Initialize core components
        self.db_path = self.db_folder / "vbsks_db.json"
        self.key_map_path = self.db_folder / "vbsks_keymap.json"
        
        # Create or load vector database
        if os.path.exists(self.db_path):
            self.vector_db = VectorDatabase.load(str(self.db_path))
            logger.info(f"Loaded existing vector database with {self.vector_db.size} vectors")
        else:
            self.vector_db = VectorDatabase(
                dimensions=dimensions, 
                size=db_size, 
                threshold=1e-6,
                use_indexing=True
            )
            logger.info(f"Created new vector database with {self.vector_db.size} vectors")
            # Save the initial database
            self.vector_db.save(str(self.db_path))
        
        # Create secure storage
        self.secure_storage = SecureStorage()
        
        # Password for securing the key map
        self.master_password = os.environ.get("VBSKS_MASTER_PASSWORD", "vbsks_default_master")
        
        # Key map to track key IDs and their positions
        self.key_map = self._load_key_map()
        
        # Create key manager
        self.key_manager = QuantumResistantKeyManager(
            vector_db=self.vector_db,
            key_length=key_length,
            threshold=1e-6,
            enable_reconfiguration=auto_reconfigure,
            reconfiguration_interval=reconfiguration_interval,
            reconfiguration_password=self.master_password
        )
        
        # Create reconfiguration controller if auto-reconfigure is enabled
        if auto_reconfigure:
            self.controller = ReconfigurationController(
                vector_db=self.vector_db,
                key_manager=self.key_manager,
                map_manager=self.key_manager.map_manager,
                secure_storage=self.secure_storage
            )
        else:
            self.controller = None
    
    def _load_key_map(self) -> Dict[str, Dict[str, Any]]:
        """Load the key map from storage or create a new one"""
        try:
            if os.path.exists(self.key_map_path):
                with open(self.key_map_path, 'r') as f:
                    key_map_data = json.load(f)
                
                # Decrypt if needed
                if isinstance(key_map_data, dict) and key_map_data.get('encrypted', False):
                    # In production, should decrypt
                    pass
                
                return key_map_data.get('keys', {})
            
            return {}
        except Exception as e:
            logger.warning(f"Error loading key map: {str(e)}. Creating new one.")
            return {}
    
    def _save_key_map(self):
        """Save the key map to storage"""
        try:
            # In production, should encrypt the key map
            key_map_data = {
                'keys': self.key_map,
                'encrypted': False
            }
            
            with open(self.key_map_path, 'w') as f:
                json.dump(key_map_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving key map: {str(e)}")
    
    def store_key(
        self,
        key_id: str,
        master_password: str,
        data: Optional[Union[str, bytes]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Store a key in the vector database.
        
        Args:
            key_id: Unique identifier for the key
            master_password: Password to protect the key
            data: Optional key data to derive from (if None, will generate random)
            metadata: Optional metadata for the key
        
        Returns:
            Dictionary with information about the stored key
        """
        # Initialize metadata if None
        if metadata is None:
            metadata = {}
        
        # Add timestamp and key_id to metadata
        metadata['key_id'] = key_id
        metadata['timestamp'] = time.time()
        
        # Create a seed for the key generation
        if data is None:
            # Generate random seed
            seed = base64.b64encode(os.urandom(32)).decode('utf-8')
        else:
            # Use provided data as seed
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            seed = base64.b64encode(data_bytes).decode('utf-8')
        
        # Generate key
        key_vectors, positions = self.key_manager.generate_key(seed)
        
        # Add to key map
        self.key_map[key_id] = {
            'positions': positions,
            'metadata': metadata,
            'created': time.time()
        }
        
        # Save key map
        self._save_key_map()
        
        # Save the database
        self.vector_db.save(str(self.db_path))
        
        # Consider secure storage of key details if needed
        key_file = self.db_folder / f"{key_id}.key"
        result = self.key_manager.save_key_data_secure(
            filename=str(key_file),
            key_vectors=key_vectors,
            positions=positions,
            metadata=metadata,
            encryption_password=master_password,
            save_map=True
        )
        
        return {
            'key_id': key_id,
            'status': 'success',
            'key_file': str(key_file),
            'result': result
        }
    
    def retrieve_key(self, key_id: str, master_password: str) -> Dict[str, Any]:
        """
        Retrieve a key from the vector database.
        
        Args:
            key_id: Unique identifier for the key
            master_password: Password to protect the key
        
        Returns:
            Dictionary with information about the retrieved key
        """
        # Check if key exists in key map
        if key_id not in self.key_map:
            return {
                'key_id': key_id,
                'status': 'error',
                'error': 'Key not found'
            }
        
        try:
            # Get positions
            key_info = self.key_map[key_id]
            positions = key_info['positions']
            
            # Retrieve key vectors
            key_vectors = self.key_manager.retrieve_key(positions)
            
            # Verify key
            is_valid = self.key_manager.verify_key(positions, key_vectors)
            
            if not is_valid:
                return {
                    'key_id': key_id,
                    'status': 'error',
                    'error': 'Key verification failed'
                }
            
            # Check if reconfiguration is needed
            needs_reconfig = False
            if self.controller:
                needs_reconfig = self.controller.check_reconfiguration_needed(positions)
            
            # Reconfigure if needed
            if needs_reconfig:
                try:
                    new_positions, result = self.controller.reconfigure(
                        positions=positions,
                        key_vectors=key_vectors,
                        requester_id=f"retrieve_key_{key_id}"
                    )
                    
                    # Update key map
                    self.key_map[key_id]['positions'] = new_positions
                    self.key_map[key_id]['last_reconfigured'] = time.time()
                    self._save_key_map()
                    
                    # Save the database
                    self.vector_db.save(str(self.db_path))
                    
                    # Also save a secure backup if needed
                    key_file = self.db_folder / f"{key_id}.key"
                    self.key_manager.save_key_data_secure(
                        filename=str(key_file),
                        key_vectors=key_vectors,
                        positions=new_positions,
                        metadata=key_info.get('metadata', {}),
                        encryption_password=master_password,
                        save_map=True
                    )
                    
                    logger.info(f"Key {key_id} automatically reconfigured")
                except Exception as e:
                    logger.error(f"Error during automatic reconfiguration: {str(e)}")
            
            # Derive cryptographic key
            crypto_key = self.key_manager.derive_cryptographic_key(key_vectors)
            
            return {
                'key_id': key_id,
                'status': 'success',
                'crypto_key': base64.b64encode(crypto_key).decode('utf-8'),
                'reconfigured': needs_reconfig
            }
        except Exception as e:
            return {
                'key_id': key_id,
                'status': 'error',
                'error': str(e)
            }
    
    def delete_key(self, key_id: str) -> Dict[str, Any]:
        """
        Delete a key from the vector database.
        
        Args:
            key_id: Unique identifier for the key
        
        Returns:
            Dictionary with status information
        """
        # Check if key exists in key map
        if key_id not in self.key_map:
            return {
                'key_id': key_id,
                'status': 'error',
                'error': 'Key not found'
            }
        
        try:
            # Get positions
            key_info = self.key_map[key_id]
            positions = key_info['positions']
            
            # Replace vectors with noise
            for pos in positions:
                noise_vector = np.random.uniform(0, 1, self.vector_db.dimensions)
                noise_vector = noise_vector / np.linalg.norm(noise_vector)  # Normalize
                self.vector_db.store_vector(pos, noise_vector, {"is_noise": True, "replaced_at": time.time()})
            
            # Remove from key map
            del self.key_map[key_id]
            
            # Save key map
            self._save_key_map()
            
            # Save the database
            self.vector_db.save(str(self.db_path))
            
            # Remove key file if exists
            key_file = self.db_folder / f"{key_id}.key"
            if os.path.exists(key_file):
                os.remove(key_file)
            
            return {
                'key_id': key_id,
                'status': 'success',
                'message': 'Key deleted'
            }
        except Exception as e:
            return {
                'key_id': key_id,
                'status': 'error',
                'error': str(e)
            }
    
    def list_keys(self) -> Dict[str, Any]:
        """
        List all keys in the key map.
        
        Returns:
            Dictionary with list of keys and metadata
        """
        keys_info = {}
        for key_id, info in self.key_map.items():
            # Create a copy without positions
            keys_info[key_id] = {
                'created': info.get('created'),
                'last_reconfigured': info.get('last_reconfigured'),
                'metadata': info.get('metadata', {})
            }
        
        return {
            'status': 'success',
            'keys': keys_info
        }
    
    def backup_database(self, backup_password: str) -> Dict[str, Any]:
        """
        Create a secure backup of the database.
        
        Args:
            backup_password: Password to protect the backup
        
        Returns:
            Dictionary with backup information
        """
        try:
            # Create backup directory
            backup_dir = self.db_folder / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = int(time.time())
            backup_file = backup_dir / f"vbsks_backup_{timestamp}.json"
            
            # Create secure backup
            result = self.vector_db.save_secure(
                filename=str(backup_file),
                split_shares=3,
                threshold_shares=2,
                encryption_password=backup_password,
                add_statistical_noise=True,
                sign_data=True
            )
            
            # Backup key map
            key_map_backup = backup_dir / f"vbsks_keymap_backup_{timestamp}.json"
            with open(key_map_backup, 'w') as f:
                json.dump(self.key_map, f, indent=2)
            
            return {
                'status': 'success',
                'backup_file': str(backup_file),
                'key_map_backup': str(key_map_backup),
                'timestamp': timestamp,
                'result': result
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def restore_database(
        self, 
        backup_file: str, 
        backup_password: str,
        key_map_backup: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Restore database from a backup.
        
        Args:
            backup_file: Path to backup file
            backup_password: Password used to protect the backup
            key_map_backup: Optional path to key map backup
        
        Returns:
            Dictionary with restore information
        """
        try:
            # Restore database
            restored_db, info = VectorDatabase.load_secure(
                filename=backup_file,
                encryption_password=backup_password
            )
            
            # Update the vector database
            self.vector_db = restored_db
            
            # Save the restored database
            self.vector_db.save(str(self.db_path))
            
            # Restore key map if provided
            if key_map_backup and os.path.exists(key_map_backup):
                with open(key_map_backup, 'r') as f:
                    self.key_map = json.load(f)
                self._save_key_map()
            
            # Update key manager and controller to use restored database
            self.key_manager.vector_db = self.vector_db
            if self.controller:
                self.controller.vector_db = self.vector_db
            
            return {
                'status': 'success',
                'dimensions': self.vector_db.dimensions,
                'size': self.vector_db.size,
                'key_map_restored': key_map_backup is not None,
                'info': info
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

# Add missing imports when detected
import time
import numpy as np 