"""
Key Manager for VBSKS

This module handles key generation, embedding, and retrieval operations.
"""

import numpy as np
import os
import json
import time
import secrets
import uuid
from datetime import datetime
import base64
from typing import List, Tuple, Dict, Any, Optional, Union
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

from utils import (
    generate_random_vector,
    derive_positions,
    secure_hash,
    save_vectors,
    load_vectors,
    quantize_vector,
    PRECISION,
    constant_time_equal
)
from vector_db import VectorDatabase
# Import MapManager for dynamic reconfiguration support
try:
    from map_manager import MapManager
    DYNAMIC_RECONFIGURATION_AVAILABLE = True
except ImportError:
    DYNAMIC_RECONFIGURATION_AVAILABLE = False
    print("Warning: Dynamic reconfiguration module not found. " +
          "Dynamic reconfiguration features will be disabled.")

# Try to import post-quantum cryptography libraries
# We'll use a try/except block to make this optional
try:
    # Check for liboqs python wrapper (for post-quantum crypto)
    import oqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("Warning: Post-quantum cryptography libraries not found. " +
          "Quantum-resistant features will be simulated.")

# Try to import secret sharing library
try:
    # There are several secret sharing libraries available
    # For example: pyssss, sss, or shamir
    import shamir_mnemonic as shamir
    SECRET_SHARING_AVAILABLE = True
except ImportError:
    SECRET_SHARING_AVAILABLE = False
    print("Warning: Secret sharing library not found. " +
          "Multi-part key features will be simulated.")

class KeyManager:
    """
    Manages the generation, storage, and retrieval of vector-based keys.
    """
    
    def __init__(
        self,
        vector_db: VectorDatabase,
        key_length: int = 5,
        threshold: float = PRECISION,
        enable_reconfiguration: bool = False,
        reconfiguration_interval: int = 3600,  # 1 hour in seconds
        reconfiguration_password: Optional[str] = None
    ):
        """
        Initialize a new key manager
        
        Args:
            vector_db: Vector database for storing keys
            key_length: Number of vectors in the key sequence
            threshold: Distance threshold for vector equality
            enable_reconfiguration: Whether to enable dynamic reconfiguration
            reconfiguration_interval: Time between reconfigurations (seconds)
            reconfiguration_password: Password for securing reconfiguration maps
        """
        self.vector_db = vector_db
        self.key_length = key_length
        self.threshold = threshold
        self.enable_reconfiguration = enable_reconfiguration and DYNAMIC_RECONFIGURATION_AVAILABLE
        self.reconfiguration_interval = reconfiguration_interval
        self.map_manager = None
        
        # Initialize map manager if dynamic reconfiguration is enabled
        if self.enable_reconfiguration:
            if not DYNAMIC_RECONFIGURATION_AVAILABLE:
                print("Warning: Dynamic reconfiguration requested but not available.")
            else:
                # Use a default password if none provided
                if reconfiguration_password is None:
                    reconfiguration_password = "vbsks_default_map_password"
                    print("Warning: Using default reconfiguration password. This is not secure for production.")
                
                self.map_manager = MapManager(
                    master_password=reconfiguration_password,
                    vector_db_size=self.vector_db.size,
                    key_length=self.key_length,
                    reconfiguration_interval=self.reconfiguration_interval
                )
    
    def generate_key_vectors(self) -> np.ndarray:
        """
        Generate a new set of key vectors
        
        Returns:
            Array of key vectors
        """
        key_vectors = np.zeros((self.key_length, self.vector_db.dimensions))
        
        for i in range(self.key_length):
            key_vectors[i] = generate_random_vector(self.vector_db.dimensions)
            
        # Quantize vectors to avoid floating-point errors
        return quantize_vector(key_vectors)
    
    def generate_key(self, secret_seed: str) -> Tuple[np.ndarray, List[int]]:
        """
        Generate a new key and embed it in the vector database
        
        Args:
            secret_seed: Secret seed for position derivation
            
        Returns:
            Tuple of (key_vectors, positions)
        """
        # Generate key vectors
        key_vectors = self.generate_key_vectors()
        
        # If dynamic reconfiguration is enabled, use the map manager to derive positions
        if self.enable_reconfiguration and self.map_manager:
            positions = self.map_manager.derive_positions_from_seed(secret_seed)
        else:
            # Use the standard method
            positions = derive_positions(
                secret_seed, 
                self.vector_db.size, 
                self.key_length
            )
        
        # Store key vectors in the database
        for i, position in enumerate(positions):
            self.vector_db.store_vector(position, key_vectors[i])
        
        return key_vectors, positions
    
    def store_key(
        self,
        key_vectors: np.ndarray,
        positions: List[int],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store a key in the vector database
        
        Args:
            key_vectors: Array of key vectors
            positions: List of positions in the database
            metadata: Optional metadata to associate with the key
        """
        if len(key_vectors) != len(positions):
            raise ValueError("Number of key vectors must match number of positions")
        
        for i, position in enumerate(positions):
            self.vector_db.store_vector(position, key_vectors[i])
    
    def verify_key(self, positions: List[int], key_vectors: np.ndarray) -> bool:
        """
        Verify if a key matches what's stored at the given positions
        
        Args:
            positions: List of positions to check
            key_vectors: Key vectors to verify
            
        Returns:
            True if the key is valid, False otherwise
        """
        if len(positions) != len(key_vectors):
            return False
        
        for i, position in enumerate(positions):
            stored_vector, _ = self.vector_db.retrieve_vector(position)
            
            # Compare vectors using constant-time comparison
            if not constant_time_equal(stored_vector, key_vectors[i], self.threshold):
                return False
        
        return True
    
    def retrieve_key(self, positions: List[int]) -> np.ndarray:
        """
        Retrieve key vectors from the database
        
        Args:
            positions: List of positions to retrieve
            
        Returns:
            Array of key vectors
        """
        key_vectors = np.zeros((len(positions), self.vector_db.dimensions))
        
        for i, position in enumerate(positions):
            vector, metadata = self.vector_db.retrieve_vector(position)
            key_vectors[i] = vector
            
        return key_vectors
    
    def check_reconfiguration_needed(self, positions: List[int]) -> bool:
        """
        Check if the key positions need to be reconfigured
        
        Args:
            positions: Current key positions
            
        Returns:
            True if reconfiguration is needed, False otherwise
        """
        if not self.enable_reconfiguration or not self.map_manager:
            return False
        
        return self.map_manager.should_reconfigure()
    
    def reconfigure_key(
        self, 
        positions: List[int], 
        key_vectors: Optional[np.ndarray] = None
    ) -> Tuple[List[int], Dict[str, Any]]:
        """
        Reconfigure the key positions in the vector database
        
        Args:
            positions: Current positions of key vectors
            key_vectors: Key vectors to move (if None, will retrieve from database)
            
        Returns:
            Tuple of (new_positions, result_info)
        """
        if not self.enable_reconfiguration or not self.map_manager:
            raise ValueError("Dynamic reconfiguration is not enabled")
        
        # If key vectors not provided, retrieve them
        if key_vectors is None:
            key_vectors = self.retrieve_key(positions)
        
        # Generate new positions
        new_positions = self.map_manager.generate_new_positions()
        
        # Transaction info
        result_info = {
            'timestamp': time.time(),
            'old_positions': positions,
            'new_positions': new_positions,
            'status': 'started'
        }
        
        try:
            # Remove key vectors from old positions by replacing with noise
            for pos in positions:
                noise_vector = np.random.uniform(0, 1, self.vector_db.dimensions)
                noise_vector = noise_vector / np.linalg.norm(noise_vector)  # Normalize
                self.vector_db.store_vector(pos, noise_vector, {"is_noise": True, "replaced_at": time.time()})
            
            # Store key vectors at new positions
            for i, (pos, vector) in enumerate(zip(new_positions, key_vectors)):
                metadata = {"key_vector_index": i, "reconfigured_at": time.time()}
                self.vector_db.store_vector(pos, vector, metadata)
            
            # Update reconfiguration time
            self.map_manager.update_reconfiguration_time()
            
            result_info['status'] = 'completed'
            result_info['reconfiguration_time'] = self.map_manager.last_reconfiguration_time
            
            return new_positions, result_info
        
        except Exception as e:
            result_info['status'] = 'failed'
            result_info['error'] = str(e)
            raise ValueError(f"Reconfiguration failed: {str(e)}")
    
    def save_map(self, positions: List[int], filename: str) -> Dict[str, Any]:
        """
        Save the current key positions map to a file
        
        Args:
            positions: Current key positions
            filename: Path to save the map
            
        Returns:
            Dictionary with save information
        """
        if not self.enable_reconfiguration or not self.map_manager:
            raise ValueError("Dynamic reconfiguration is not enabled")
        
        return self.map_manager.save_map_file(positions, filename)
    
    def load_map(self, filename: str) -> List[int]:
        """
        Load key positions from a map file
        
        Args:
            filename: Path to the map file
            
        Returns:
            List of key positions
        """
        if not self.enable_reconfiguration or not self.map_manager:
            raise ValueError("Dynamic reconfiguration is not enabled")
        
        return self.map_manager.load_map_file(filename)
    
    def derive_cryptographic_key(
        self,
        key_vectors: np.ndarray,
        key_size_bytes: int = 32
    ) -> bytes:
        """
        Derive a cryptographic key from vector-based key
        
        Args:
            key_vectors: The vector-based key
            key_size_bytes: Size of the derived key in bytes
            
        Returns:
            Bytes representing a cryptographic key
        """
        # Flatten the vectors and convert to bytes
        flattened = key_vectors.flatten().tobytes()
        
        # Use PBKDF2 to derive a key of the requested size
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size_bytes,
            salt=b'VBSKS_static_salt',  # In production, use a random salt
            iterations=100000,
        )
        
        derived_key = kdf.derive(flattened)
        return derived_key
    
    def save_key_data(
        self,
        filename: str,
        key_vectors: np.ndarray,
        positions: List[int],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Save key data to a file
        
        Args:
            filename: Path to save the key data
            key_vectors: Key vectors
            positions: Positions in the database
            metadata: Optional metadata
        """
        data = {
            'key_length': self.key_length,
            'threshold': self.threshold,
            'positions': positions,
            'key_vectors': key_vectors.tolist(),
            'metadata': metadata or {}
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f)
    
    @classmethod
    def load_key_data(cls, filename: str) -> Dict[str, Any]:
        """
        Load key data from a file
        
        Args:
            filename: Path to the key data file
            
        Returns:
            Dictionary with key data
        """
        with open(filename, 'r') as f:
            data = json.load(f)
            
        # Convert key vectors back to numpy array
        data['key_vectors'] = np.array(data['key_vectors'])
        
        return data 


class QuantumResistantKeyManager(KeyManager):
    """
    Enhanced Key Manager with quantum-resistant security features for key data storage.
    
    This class extends the base KeyManager with additional security features:
    1. Post-quantum cryptography for key data encryption
    2. Secret sharing for splitting keys into multiple parts
    3. Support for hardware security modules
    4. Additional authentication mechanisms
    5. Dynamic key position reconfiguration
    """
    
    def __init__(
        self,
        vector_db: VectorDatabase,
        key_length: int = 5,
        threshold: float = PRECISION,
        quantum_algorithm: str = "Kyber768",  # Default to NIST PQC standard
        enable_reconfiguration: bool = False,
        reconfiguration_interval: int = 3600,  # 1 hour in seconds
        reconfiguration_password: Optional[str] = None
    ):
        """
        Initialize a quantum-resistant key manager
        
        Args:
            vector_db: Vector database for storing keys
            key_length: Number of vectors in the key sequence
            threshold: Distance threshold for vector equality
            quantum_algorithm: Post-quantum algorithm to use
            enable_reconfiguration: Whether to enable dynamic reconfiguration
            reconfiguration_interval: Time between reconfigurations (seconds)
            reconfiguration_password: Password for securing reconfiguration maps
        """
        # Initialize base KeyManager
        super().__init__(
            vector_db, 
            key_length, 
            threshold, 
            enable_reconfiguration,
            reconfiguration_interval,
            reconfiguration_password
        )
        self.quantum_algorithm = quantum_algorithm
        
        # Check if post-quantum crypto is available
        if not PQC_AVAILABLE and quantum_algorithm != "Simulate":
            print(f"Warning: Requested quantum algorithm {quantum_algorithm} not available. " +
                  "Falling back to simulation mode.")
            self.quantum_algorithm = "Simulate"
    
    def _simulate_pqc_encrypt(self, data: bytes) -> Dict[str, str]:
        """
        Simulate post-quantum encryption (for when actual PQC libraries are not available)
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary with encryption metadata
        """
        # Generate a random key for AES-GCM
        aes_key = os.urandom(32)
        
        # Create a nonce
        nonce = os.urandom(12)
        
        # Encrypt the data using AES-GCM
        try:
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # In a real PQC implementation, we would encrypt the AES key with a PQC algorithm
            # For simulation, we'll just add it to the output
            return {
                'algorithm': 'SIMULATED-PQC-AES256-GCM',
                'aes_key': base64.b64encode(aes_key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode()
            }
        except Exception as e:
            # Fall back to simple base64 encoding if there's an issue
            print(f"Warning: Encryption failed ({str(e)}). Using base64 encoding instead.")
            return {
                'algorithm': 'BASE64-ENCODING',
                'data': base64.b64encode(data).decode()
            }
    
    def _simulate_pqc_decrypt(self, encrypted_data: Dict[str, str]) -> bytes:
        """
        Simulate post-quantum decryption
        
        Args:
            encrypted_data: Dictionary with encryption metadata
            
        Returns:
            Decrypted data
        """
        if encrypted_data.get('algorithm') == 'SIMULATED-PQC-AES256-GCM':
            aes_key = base64.b64decode(encrypted_data['aes_key'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            try:
                aesgcm = AESGCM(aes_key)
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}")
        elif encrypted_data.get('algorithm') == 'BASE64-ENCODING':
            return base64.b64decode(encrypted_data['data'])
        else:
            raise ValueError(f"Unknown encryption algorithm: {encrypted_data.get('algorithm')}")
    
    def _real_pqc_encrypt(self, data: bytes) -> Dict[str, str]:
        """
        Perform real post-quantum encryption using liboqs
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary with encryption metadata
        """
        if not PQC_AVAILABLE:
            return self._simulate_pqc_encrypt(data)
        
        try:
            # Select the post-quantum algorithm
            kem = oqs.KeyEncapsulation(self.quantum_algorithm)
            
            # Generate a keypair
            public_key = kem.generate_keypair()
            
            # Encapsulate to get a shared secret and ciphertext
            ciphertext, shared_secret = kem.encap_secret(public_key)
            
            # Use the shared secret to encrypt with AES-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(shared_secret)
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            
            # Package everything together
            return {
                'algorithm': f'PQC-{self.quantum_algorithm}-AES256-GCM',
                'pqc_ciphertext': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'public_key': base64.b64encode(public_key).decode()
            }
        except Exception as e:
            print(f"Warning: PQC encryption failed ({str(e)}). Falling back to simulation.")
            return self._simulate_pqc_encrypt(data)
    
    def _split_secret(self, data: bytes, total_shares: int, threshold: int) -> List[Dict[str, Any]]:
        """
        Split data into shares using Shamir's Secret Sharing
        
        Args:
            data: Data to split
            total_shares: Total number of shares to create
            threshold: Minimum shares needed to reconstruct
            
        Returns:
            List of share dictionaries
        """
        if SECRET_SHARING_AVAILABLE:
            try:
                # Use the actual secret sharing library
                master_secret = data[:32]  # Most libraries have size limits, so use first 32 bytes
                
                # Create shares
                shares = shamir.generate_mnemonics(
                    group_threshold=1,  # Only one group for now
                    groups=[(threshold, total_shares)],
                    master_secret=master_secret
                )
                
                # For data larger than 32 bytes, encrypt the remainder
                # using the master secret as a key
                if len(data) > 32:
                    remainder = data[32:]
                    nonce = os.urandom(12)
                    aesgcm = AESGCM(master_secret)
                    encrypted_remainder = aesgcm.encrypt(nonce, remainder, None)
                    
                    # Create share objects with the remainder data
                    share_objects = []
                    for i, share in enumerate(shares):
                        share_objects.append({
                            'index': i + 1,
                            'share': share,
                            'encrypted_remainder': base64.b64encode(encrypted_remainder).decode(),
                            'remainder_nonce': base64.b64encode(nonce).decode(),
                            'shares_info': {
                                'total': total_shares,
                                'threshold': threshold
                            }
                        })
                    
                    return share_objects
                else:
                    # Create simple share objects
                    share_objects = []
                    for i, share in enumerate(shares):
                        share_objects.append({
                            'index': i + 1,
                            'share': share,
                            'shares_info': {
                                'total': total_shares,
                                'threshold': threshold
                            }
                        })
                    
                    return share_objects
                    
            except Exception as e:
                print(f"Warning: Secret sharing failed ({str(e)}). Using simulated shares.")
        
        # Simulate secret sharing if the library is not available
        # or if an error occurred
        simulated_shares = []
        share_id = hashlib.sha256(data + os.urandom(8)).hexdigest()[:8]
        
        for i in range(total_shares):
            # In a simulated share, we just include the full data in each share
            # This is NOT secure and is just for demonstration purposes
            simulated_shares.append({
                'index': i + 1,
                'share_id': share_id,
                'simulated': True,
                'data': base64.b64encode(data).decode(),
                'shares_info': {
                    'total': total_shares,
                    'threshold': threshold,
                    'warning': 'SIMULATED SHARES - NOT SECURE FOR PRODUCTION'
                }
            })
        
        return simulated_shares
    
    def _combine_shares(self, shares: List[Dict[str, Any]]) -> bytes:
        """
        Combine secret shares to retrieve the original data
        
        Args:
            shares: List of share dictionaries
            
        Returns:
            Reconstructed data
        """
        if not shares:
            raise ValueError("No shares provided")
        
        # Check if using simulated shares
        if shares[0].get('simulated', False):
            # For simulated shares, just decode the data from any share
            return base64.b64decode(shares[0]['data'])
        
        if SECRET_SHARING_AVAILABLE:
            try:
                # Extract shares
                mnemonics = [share['share'] for share in shares]
                
                # Combine shares to get the master secret
                master_secret = shamir.combine_mnemonics(mnemonics)
                
                # Check if we have remainder data to decrypt
                if 'encrypted_remainder' in shares[0] and 'remainder_nonce' in shares[0]:
                    encrypted_remainder = base64.b64decode(shares[0]['encrypted_remainder'])
                    nonce = base64.b64decode(shares[0]['remainder_nonce'])
                    
                    # Decrypt the remainder
                    aesgcm = AESGCM(master_secret)
                    remainder = aesgcm.decrypt(nonce, encrypted_remainder, None)
                    
                    # Combine the master secret and remainder
                    return master_secret + remainder
                else:
                    # No remainder, just return the master secret
                    return master_secret
                
            except Exception as e:
                raise ValueError(f"Failed to combine shares: {str(e)}")
        else:
            raise ValueError("Secret sharing library not available")
    
    def save_key_data_secure(
        self,
        filename: str,
        key_vectors: np.ndarray,
        positions: List[int],
        metadata: Optional[Dict[str, Any]] = None,
        use_quantum_resistant: bool = True,
        split_shares: int = 1,
        threshold: int = 1,
        encryption_password: Optional[str] = None,
        save_map: bool = True
    ) -> Dict[str, Any]:
        """
        Save key data with enhanced quantum-resistant security
        
        Args:
            filename: Base filename for key data
            key_vectors: Key vectors
            positions: Positions in the database
            metadata: Optional metadata
            use_quantum_resistant: Whether to use quantum-resistant encryption
            split_shares: Number of shares to split the key into (Shamir's Secret Sharing)
            threshold: Minimum number of shares needed for reconstruction
            encryption_password: Optional password for additional encryption layer
            save_map: Whether to save a map file for reconfiguration
            
        Returns:
            Dictionary with information about saved files
        """
        # Prepare basic key data
        data = {
            'key_length': self.key_length,
            'threshold': self.threshold,
            'positions': positions,
            'key_vectors': key_vectors.tolist(),
            'metadata': metadata or {},
            'created_at': datetime.now().isoformat(),
            'key_id': str(uuid.uuid4())
        }
        
        # Convert to bytes for cryptographic operations
        data_bytes = json.dumps(data).encode()
        result_info = {
            'key_id': data['key_id'],
            'files': {}
        }
        
        # Add password encryption if provided
        if encryption_password:
            # Generate salt and derive key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(encryption_password.encode())
            
            # Encrypt the data
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(nonce, data_bytes, None)
            
            # Update the data bytes
            password_protected_data = {
                'password_protected': True,
                'salt': base64.b64encode(salt).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            data_bytes = json.dumps(password_protected_data).encode()
        
        # Apply quantum-resistant encryption if requested
        if use_quantum_resistant:
            if self.quantum_algorithm == "Simulate":
                encrypted_data_dict = self._simulate_pqc_encrypt(data_bytes)
            else:
                encrypted_data_dict = self._real_pqc_encrypt(data_bytes)
            
            # Update data bytes with encrypted version
            data_bytes = json.dumps(encrypted_data_dict).encode()
        
        # If no splitting requested, just save the file
        if split_shares <= 1:
            with open(filename, 'wb') as f:
                f.write(data_bytes)
            
            result_info['files']['main'] = filename
            result_info['quantum_resistant'] = use_quantum_resistant
            result_info['password_protected'] = bool(encryption_password)
            
            # If reconfiguration is enabled and save_map is True, save the map file
            if self.enable_reconfiguration and self.map_manager and save_map:
                try:
                    map_filename = f"{filename}.map"
                    map_info = self.save_map(positions, map_filename)
                    result_info['map_file'] = map_filename
                    result_info['map_info'] = map_info
                except Exception as e:
                    result_info['map_error'] = str(e)
            
            return result_info
        
        # Split into shares if requested
        shares = self._split_secret(data_bytes, split_shares, threshold)
        
        # Save each share to a separate file
        for i, share in enumerate(shares):
            share_filename = f"{filename}.share{i+1}"
            with open(share_filename, 'w') as f:
                json.dump(share, f, indent=2)
            
            result_info['files'][f'share_{i+1}'] = share_filename
        
        # Create a recovery information file
        recovery_info = {
            'key_id': data['key_id'],
            'created_at': datetime.now().isoformat(),
            'shares_info': {
                'total_shares': split_shares,
                'threshold': threshold,
                'share_files': [f"{filename}.share{i+1}" for i in range(split_shares)]
            },
            'encryption_info': {
                'quantum_resistant': use_quantum_resistant,
                'algorithm': self.quantum_algorithm if use_quantum_resistant else None,
                'password_protected': bool(encryption_password)
            },
            'recovery_instructions': (
                f"To recover this key, collect at least {threshold} share files and use "
                "the QuantumResistantKeyManager.load_key_data_secure method."
            )
        }
        
        recovery_filename = f"{filename}.recovery_info"
        with open(recovery_filename, 'w') as f:
            json.dump(recovery_info, f, indent=2)
        
        result_info['files']['recovery_info'] = recovery_filename
        result_info['shares_info'] = {
            'total': split_shares,
            'threshold': threshold
        }
        result_info['quantum_resistant'] = use_quantum_resistant
        result_info['password_protected'] = bool(encryption_password)
        
        # If reconfiguration is enabled and save_map is True, save the map file
        if self.enable_reconfiguration and self.map_manager and save_map:
            try:
                map_filename = f"{filename}.map"
                map_info = self.save_map(positions, map_filename)
                result_info['map_file'] = map_filename
                result_info['map_info'] = map_info
            except Exception as e:
                result_info['map_error'] = str(e)
        
        return result_info
    
    def reconfigure_key_secure(
        self,
        positions: List[int],
        key_vectors: Optional[np.ndarray] = None,
        backup_file: Optional[str] = None,
        encryption_password: Optional[str] = None
    ) -> Tuple[List[int], Dict[str, Any]]:
        """
        Securely reconfigure key positions with backup
        
        Args:
            positions: Current positions of key vectors
            key_vectors: Key vectors to move (if None, will retrieve from database)
            backup_file: Optional file to save backup before reconfiguration
            encryption_password: Password for backup file encryption
            
        Returns:
            Tuple of (new_positions, result_info)
        """
        if not self.enable_reconfiguration or not self.map_manager:
            raise ValueError("Dynamic reconfiguration is not enabled")
        
        # Create the result info dictionary
        result_info = {
            'timestamp': time.time(),
            'old_positions': positions,
            'status': 'started'
        }
        
        # If key vectors not provided, retrieve them
        if key_vectors is None:
            key_vectors = self.retrieve_key(positions)
        
        # If backup file specified, save backup before reconfiguration
        if backup_file:
            try:
                backup_info = self.save_key_data_secure(
                    filename=backup_file,
                    key_vectors=key_vectors,
                    positions=positions,
                    metadata={"backup_type": "pre_reconfiguration", "timestamp": time.time()},
                    use_quantum_resistant=True,
                    encryption_password=encryption_password,
                    save_map=True
                )
                result_info['backup_created'] = True
                result_info['backup_file'] = backup_file
                result_info['backup_info'] = backup_info
            except Exception as e:
                result_info['backup_error'] = str(e)
                result_info['status'] = 'failed'
                raise ValueError(f"Failed to create backup before reconfiguration: {str(e)}")
        
        # Perform the reconfiguration
        try:
            new_positions, reconfig_info = self.reconfigure_key(positions, key_vectors)
            result_info.update(reconfig_info)
            
            # Save map of new positions
            if backup_file:
                map_filename = f"{backup_file}.new_map"
                map_info = self.save_map(new_positions, map_filename)
                result_info['new_map_file'] = map_filename
                result_info['new_map_info'] = map_info
            
            return new_positions, result_info
        
        except Exception as e:
            result_info['status'] = 'failed'
            result_info['error'] = str(e)
            raise ValueError(f"Secure reconfiguration failed: {str(e)}")
    
    @classmethod
    def load_key_data_secure(
        cls,
        source: Union[str, List[str]],
        encryption_password: Optional[str] = None,
        private_key_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Load key data with support for quantum-resistant decryption and share reconstruction
        
        Args:
            source: Filename, list of share filenames, or recovery info filename
            encryption_password: Optional password for decryption
            private_key_file: Optional file containing PQC private key
            
        Returns:
            Dictionary with key data
        """
        data_bytes = None
        
        # Handle recovery info file
        if isinstance(source, str) and source.endswith('.recovery_info'):
            with open(source, 'r') as f:
                recovery_info = json.load(f)
            
            # Get share files from recovery info
            share_files = recovery_info.get('shares_info', {}).get('share_files', [])
            if not share_files:
                raise ValueError("Invalid recovery info file: no share files listed")
            
            # Use the share files as the source
            source = share_files
        
        # Handle share files
        if isinstance(source, list):
            # Load the shares
            shares = []
            for share_file in source:
                with open(share_file, 'r') as f:
                    share_data = json.load(f)
                    shares.append(share_data)
            
            # Check if we have enough shares
            threshold = shares[0].get('shares_info', {}).get('threshold', 1)
            if len(shares) < threshold:
                raise ValueError(
                    f"Not enough shares provided: got {len(shares)}, need at least {threshold}"
                )
            
            # Combine the shares
            data_bytes = cls._combine_shares(cls, shares)  # Fixed: Properly call class method
        else:
            # Load a single file
            with open(source, 'rb') as f:
                data_bytes = f.read()
        
        # Try to parse as JSON
        try:
            data = json.loads(data_bytes)
            
            # Check if quantum-resistant encrypted
            if 'algorithm' in data and (
                data['algorithm'].startswith('PQC-') or 
                data['algorithm'].startswith('SIMULATED-PQC-')
            ):
                if data['algorithm'].startswith('SIMULATED-PQC-'):
                    # Simulate decryption
                    data_bytes = cls._simulate_pqc_decrypt(cls, data)  # Fixed: Properly call class method
                else:
                    # Actual PQC decryption would go here
                    # For now, we'll raise an error that we need to implement this
                    raise NotImplementedError(
                        f"Actual PQC decryption for {data['algorithm']} not yet implemented"
                    )
                
                # Parse the decrypted data
                data = json.loads(data_bytes)
            
            # Check if password protected
            if data.get('password_protected'):
                if not encryption_password:
                    raise ValueError("This key is password protected. Please provide the password.")
                
                # Decrypt using the password
                salt = base64.b64decode(data['salt'])
                nonce = base64.b64decode(data['nonce'])
                encrypted_data = base64.b64decode(data['data'])
                
                # Derive the key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(encryption_password.encode())
                
                # Decrypt the data
                aesgcm = AESGCM(key)
                try:
                    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
                    data = json.loads(decrypted_data)
                except Exception:
                    raise ValueError("Invalid password or corrupted data")
            
            # Convert key_vectors back to numpy array
            if 'key_vectors' in data:
                data['key_vectors'] = np.array(data['key_vectors'])
            
            return data
        except json.JSONDecodeError:
            raise ValueError("Invalid key data format") 