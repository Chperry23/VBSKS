"""
Map Manager for VBSKS

This module provides functionality for secure map storage and dynamic reconfiguration
of key vector positions within the vector database.
"""

import os
import json
import time
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MapManager')

class MapManager:
    """
    Manages the secure storage and dynamic reconfiguration of key vector positions
    within the vector database.
    """
    
    def __init__(
        self,
        master_password: str,
        vector_db_size: int,
        key_length: int,
        reconfiguration_interval: Optional[int] = None  # in seconds
    ):
        """
        Initialize the map manager.
        
        Args:
            master_password: Password used to encrypt the map
            vector_db_size: Size of the vector database
            key_length: Number of key vectors
            reconfiguration_interval: Interval between automatic reconfigurations (in seconds)
        """
        self.vector_db_size = vector_db_size
        self.key_length = key_length
        self.reconfiguration_interval = reconfiguration_interval
        self.last_reconfiguration_time = time.time()
        
        # Derive a master key from the password
        self.master_key = self._derive_master_key(master_password)
        
        logger.info(f"Initialized MapManager with database size {vector_db_size} and key length {key_length}")
        
    def _derive_master_key(self, password: str) -> bytes:
        """Derive a master key from the password using PBKDF2."""
        salt = b'VBSKS_MAP_MANAGER'  # Fixed salt for consistent key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000000,  # High number of iterations for security
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_map(self, positions: List[int]) -> Dict[str, str]:
        """
        Encrypt the map of key vector positions.
        
        Args:
            positions: List of positions in the vector database
            
        Returns:
            Dictionary with encrypted map data
        """
        # Ensure the map is valid
        if len(positions) != self.key_length:
            raise ValueError(f"Expected {self.key_length} positions, got {len(positions)}")
        
        # Convert positions to bytes
        positions_bytes = json.dumps(positions).encode()
        
        # Generate a nonce
        nonce = os.urandom(12)
        
        # Encrypt the positions
        cipher = AESGCM(self.master_key)
        ciphertext = cipher.encrypt(nonce, positions_bytes, None)
        
        # Create the encrypted map data
        map_data = {
            'timestamp': time.time(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'vector_db_size': self.vector_db_size,
            'key_length': self.key_length
        }
        
        return map_data
    
    def decrypt_map(self, map_data: Dict[str, str]) -> List[int]:
        """
        Decrypt the map of key vector positions.
        
        Args:
            map_data: Dictionary with encrypted map data
            
        Returns:
            List of positions in the vector database
        """
        # Extract the required data
        nonce = base64.b64decode(map_data['nonce'])
        ciphertext = base64.b64decode(map_data['ciphertext'])
        
        # Decrypt the positions
        cipher = AESGCM(self.master_key)
        positions_bytes = cipher.decrypt(nonce, ciphertext, None)
        
        # Convert bytes to positions
        positions = json.loads(positions_bytes.decode())
        
        return positions
    
    def derive_positions_from_seed(self, seed: str) -> List[int]:
        """
        Derive positions deterministically from a seed
        
        Args:
            seed: Seed string for the position derivation
            
        Returns:
            List of positions
        """
        # Hash the seed to get a numeric value for the random state
        seed_bytes = seed.encode('utf-8') if isinstance(seed, str) else seed
        seed_hash = int(hashlib.sha256(seed_bytes).hexdigest(), 16) % (2**32 - 1)
        
        # Create a seeded random number generator
        rng = np.random.RandomState(seed_hash)
        
        # Generate unique positions
        positions = []
        while len(positions) < self.key_length:
            # Generate a candidate position
            pos = rng.randint(0, self.vector_db_size)
            
            # Add it if not already selected
            if pos not in positions:
                positions.append(pos)
        
        return positions
    
    def generate_new_positions(self) -> List[int]:
        """
        Generate new random positions for key vectors.
        
        Returns:
            List of new positions in the vector database
        """
        # Use cryptographic random for security
        positions = []
        available_indices = set(range(self.vector_db_size))
        
        for _ in range(self.key_length):
            if not available_indices:
                raise ValueError("Not enough space in vector database")
            
            # Convert to list for random.choice
            available_list = list(available_indices)
            # Use secure random choice
            index = available_list[int.from_bytes(os.urandom(4), byteorder='big') % len(available_list)]
            positions.append(index)
            available_indices.remove(index)
        
        logger.info(f"Generated {self.key_length} new positions for key vectors")
        return positions
    
    def should_reconfigure(self) -> bool:
        """
        Check if reconfiguration should be triggered based on time interval.
        
        Returns:
            True if reconfiguration should be triggered, False otherwise
        """
        if self.reconfiguration_interval is None:
            return False
        
        current_time = time.time()
        elapsed_time = current_time - self.last_reconfiguration_time
        
        return elapsed_time >= self.reconfiguration_interval
    
    def update_reconfiguration_time(self):
        """Update the last reconfiguration time to the current time."""
        self.last_reconfiguration_time = time.time()
        logger.info(f"Updated last reconfiguration time to {self.last_reconfiguration_time}")
    
    def save_map_file(self, positions: List[int], filename: str) -> Dict[str, Any]:
        """
        Save the encrypted map to a file.
        
        Args:
            positions: List of positions in the vector database
            filename: Path to save the map file
            
        Returns:
            Dictionary with information about the saved map
        """
        # Encrypt the map
        map_data = self.encrypt_map(positions)
        
        # Add file metadata
        map_file = {
            'type': 'VBSKS_MAP',
            'version': '1.0',
            'created_at': time.time(),
            'map_data': map_data,
            'checksums': {
                'positions': hashlib.sha256(json.dumps(positions).encode()).hexdigest()
            }
        }
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(map_file, f, indent=2)
        
        logger.info(f"Saved map file to {filename}")
        
        return {
            'filename': filename,
            'timestamp': map_file['created_at'],
            'vector_db_size': self.vector_db_size,
            'key_length': self.key_length
        }

    def load_map_file(self, filename: str) -> List[int]:
        """
        Load the encrypted map from a file.
        
        Args:
            filename: Path to the map file
            
        Returns:
            List of positions in the vector database
        """
        # Read the file
        with open(filename, 'r') as f:
            map_file = json.load(f)
        
        # Verify the file format
        if map_file.get('type') != 'VBSKS_MAP':
            raise ValueError("Invalid map file format")
        
        # Extract the map data
        map_data = map_file['map_data']
        
        # Decrypt the map
        positions = self.decrypt_map(map_data)
        
        # Verify the checksum
        expected_checksum = map_file['checksums']['positions']
        actual_checksum = hashlib.sha256(json.dumps(positions).encode()).hexdigest()
        
        if expected_checksum != actual_checksum:
            raise ValueError("Map file checksum verification failed")
        
        logger.info(f"Loaded map file from {filename}")
        return positions 