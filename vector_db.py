"""
Vector Database for VBSKS

This module implements a noise-filled vector database for secure key storage.
It includes methods for securely saving and loading the database with enhanced protection.
"""

import json
import numpy as np
import time
import secrets
import random
import hashlib
import datetime
from typing import List, Dict, Any, Tuple, Optional, Union

from utils import (
    constant_time_equal,
    generate_random_vector,
    quantize_vector
)

# Try to import FAISS for efficient vector search
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("Warning: FAISS not found. Using slower vector search.")

class VectorDatabase:
    """
    A database of vectors with built-in search capabilities
    
    This class stores vectors with associated metadata and provides methods
    for finding the closest vectors to a given query vector.
    """
    
    def __init__(
        self, 
        dimensions: int, 
        size: int = 0,
        threshold: float = 1e-6,
        use_indexing: bool = True
    ):
        """
        Initialize a vector database
        
        Args:
            dimensions: Dimensionality of vectors to store
            size: Initial size of the database (filled with random vectors)
            threshold: Distance threshold for considering vectors a match
            use_indexing: Whether to use FAISS indexing (if available)
        """
        self.dimensions = dimensions
        self.size = size
        self.threshold = threshold
        self.use_indexing = use_indexing and FAISS_AVAILABLE
        
        # Initialize vectors storage
        if size > 0:
            self.vectors = np.zeros((size, dimensions))
            # Populate with random noise
            for i in range(size):
                self.vectors[i] = generate_random_vector(dimensions)
        else:
            self.vectors = np.zeros((0, dimensions))
        
        self.metadata = [{} for _ in range(size)]
        
        # Initialize index if using FAISS
        if self.use_indexing:
            self._build_index()
        else:
            self.index = None
    
    def _build_index(self):
        """Build or rebuild the FAISS index"""
        if not FAISS_AVAILABLE:
            return
        
        self.index = faiss.IndexFlatL2(self.dimensions)
        if self.size > 0:
            self.index.add(self.vectors.astype(np.float32))
    
    def store_vector(self, position: int, vector: np.ndarray, metadata: Dict[str, Any] = None) -> None:
        """
        Store a vector at a specific position in the database
        
        Args:
            position: Index position to store the vector
            vector: The vector to store
            metadata: Metadata to associate with the vector
        """
        if position < 0 or position >= self.size:
            raise ValueError(f"Position {position} out of range")
        
        if vector.shape != (self.dimensions,):
            raise ValueError(f"Vector must have shape ({self.dimensions},)")
        
        # Store the quantized vector to avoid floating-point errors
        self.vectors[position] = quantize_vector(vector)
        if metadata is not None:
            self.metadata[position] = metadata
        
        # Update the index if using FAISS
        if self.use_indexing and self.index is not None:
            # For simplicity, rebuild the entire index
            # In a production system, you might want to update just the changed vector
            self._build_index()
    
    def add_vector(self, vector: np.ndarray, metadata: Dict[str, Any] = None) -> int:
        """
        Add a new vector to the database
        
        Args:
            vector: Vector to add
            metadata: Metadata to associate with the vector
            
        Returns:
            Index of the added vector
        """
        if vector.shape != (self.dimensions,):
            raise ValueError(f"Vector must have shape ({self.dimensions},)")
        
        # Normalize the vector
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        
        # Create a new slot
        position = self.size
        
        # Resize the vectors array
        new_vectors = np.zeros((position + 1, self.dimensions))
        if self.size > 0:
            new_vectors[:position] = self.vectors
        new_vectors[position] = quantize_vector(vector)
        self.vectors = new_vectors
        
        # Add metadata
        self.metadata.append(metadata or {})
        
        # Update size
        self.size += 1
        
        # Update index if needed
        if self.use_indexing:
            self._build_index()
        
        return position
    
    def retrieve_vector(self, position: int) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Retrieve a vector from a specific position
        
        Args:
            position: Index position to retrieve
            
        Returns:
            Tuple of (vector, metadata)
        """
        if position < 0 or position >= self.size:
            raise ValueError(f"Position {position} out of range")
        
        # Add small random delay to mitigate timing attacks
        time.sleep(secrets.SystemRandom().uniform(0.0005, 0.001))
        
        return self.vectors[position].copy(), self.metadata[position]
    
    def find_closest_vector(
        self, 
        query_vector: np.ndarray,
        limit: int = 1, 
        constant_time: bool = False
    ) -> List[Tuple[int, float, Dict[str, Any]]]:
        """
        Find the closest vectors to a query vector
        
        Args:
            query_vector: Query vector
            limit: Maximum number of results to return
            constant_time: Whether to use constant time search (slower but more secure)
            
        Returns:
            List of tuples (index, distance, metadata) sorted by distance
        """
        if query_vector.shape != (self.dimensions,):
            raise ValueError(f"Query vector must have shape ({self.dimensions},)")
        
        # Normalize the query vector
        norm = np.linalg.norm(query_vector)
        if norm > 0:
            query_vector = query_vector / norm
        
        # If FAISS is available and constant time is not required, use it
        if self.use_indexing and not constant_time and self.index is not None:
            # Convert to float32 for FAISS
            query_float32 = np.array([query_vector], dtype=np.float32)
            
            # Perform the search
            distances, indices = self.index.search(query_float32, min(limit, self.size))
            
            # Convert to list of tuples
            results = []
            for i in range(len(indices[0])):
                idx = indices[0][i]
                dist = distances[0][i]
                if dist <= self.threshold:
                    results.append((int(idx), float(dist), self.metadata[idx]))
            
            return results
        else:
            # Compute distances to all vectors
            distances = []
            for i in range(self.size):
                # Compute Euclidean distance
                vector = self.vectors[i]
                dist = np.linalg.norm(vector - query_vector)
                distances.append((i, dist))
            
            # Sort by distance
            if constant_time:
                # In constant time mode, we compute all distances then sort
                distances.sort(key=lambda x: x[1])
                results = [(i, d, self.metadata[i]) for i, d in distances[:limit] if d <= self.threshold]
            else:
                # In non-constant time mode, we can sort and return early
                distances.sort(key=lambda x: x[1])
                results = [(i, d, self.metadata[i]) for i, d in distances[:limit] if d <= self.threshold]
            
            return results
    
    def to_json(self) -> str:
        """
        Convert the database to a JSON string
        
        Returns:
            JSON string representation of the database
        """
        # Convert vectors to lists for JSON serialization
        vectors_list = self.vectors.tolist()
        
        # Create a dictionary representation
        db_dict = {
            'dimensions': self.dimensions,
            'size': self.size,
            'threshold': self.threshold,
            'use_indexing': self.use_indexing,
            'vectors': vectors_list,
            'metadata': self.metadata
        }
        
        # Convert to JSON
        return json.dumps(db_dict)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'VectorDatabase':
        """
        Create a database from a JSON string
        
        Args:
            json_str: JSON string representation of the database
            
        Returns:
            Vector database instance
        """
        # Parse the JSON
        db_dict = json.loads(json_str)
        
        # Create a new database with initial size 0
        db = cls(
            dimensions=db_dict['dimensions'],
            size=0,
            threshold=db_dict['threshold'],
            use_indexing=db_dict['use_indexing']
        )
        
        # Replace the vectors array
        db.vectors = np.array(db_dict['vectors'])
        db.size = db_dict['size']
        
        # Replace metadata
        db.metadata = db_dict['metadata']
        
        # Rebuild index if needed
        if db.use_indexing:
            db._build_index()
        
        return db
    
    def save(self, filename: str) -> None:
        """
        Save the database to a file
        
        Args:
            filename: Filename to save to
        """
        with open(filename, 'w') as f:
            f.write(self.to_json())
    
    @classmethod
    def load(cls, filename: str) -> 'VectorDatabase':
        """
        Load a database from a file
        
        Args:
            filename: Filename to load from
            
        Returns:
            Vector database instance
        """
        with open(filename, 'r') as f:
            json_str = f.read()
        
        return cls.from_json(json_str)
    
    def save_secure(
        self, 
        filename: str,
        split_shares: int = 1,
        threshold_shares: int = 1,
        encryption_password: Optional[str] = None,
        add_statistical_noise: bool = False,
        sign_data: bool = True
    ) -> Dict[str, Any]:
        """
        Save the database with security features
        
        Args:
            filename: Filename to save to
            split_shares: Number of shares to split the file into
            threshold_shares: Minimum number of shares needed to reconstruct
            encryption_password: Password for encryption
            add_statistical_noise: Whether to add statistical noise
            sign_data: Whether to add a digital signature
            
        Returns:
            Dictionary with information about the saved database
        """
        # Import here to avoid circular imports
        from secure_storage import SecureStorage
        
        # Create a secure storage instance
        storage = SecureStorage()
        
        # Save the database securely
        result = storage.secure_save_vector_db(
            vector_db=self,
            filename=filename,
            split_shares=split_shares,
            threshold_shares=threshold_shares,
            encryption_password=encryption_password,
            add_statistical_noise=add_statistical_noise,
            sign_data=sign_data
        )
        
        return result
    
    @classmethod
    def load_secure(
        cls,
        filename: Optional[str] = None,
        recovery_info_file: Optional[str] = None,
        share_files: Optional[List[str]] = None,
        encryption_password: Optional[str] = None,
        verify_signature: bool = True
    ) -> Tuple['VectorDatabase', Dict[str, Any]]:
        """
        Load a database with security features
        
        Args:
            filename: Filename to load from
            recovery_info_file: Recovery info filename
            share_files: List of share filenames
            encryption_password: Password for decryption
            verify_signature: Whether to verify the digital signature
            
        Returns:
            Tuple of (vector database instance, result info)
        """
        # Import here to avoid circular imports
        from secure_storage import SecureStorage
        
        # Create a secure storage instance
        storage = SecureStorage()
        
        # Load the database securely
        vector_db, result_info = storage.secure_load_vector_db(
            filename=filename,
            recovery_info_file=recovery_info_file,
            share_files=share_files,
            encryption_password=encryption_password,
            verify_signature=verify_signature
        )
        
        return vector_db, result_info
    
    def add_noise_vectors(self, count: int, similarity_range: Tuple[float, float] = (0.5, 0.9)) -> List[int]:
        """
        Add noise vectors to the database for obfuscation
        
        Args:
            count: Number of noise vectors to add
            similarity_range: Range of similarities to existing vectors
            
        Returns:
            List of indices of added noise vectors
        """
        if self.size == 0:
            raise ValueError("Cannot add noise vectors to an empty database")
        
        indices = []
        for _ in range(count):
            # Choose a random existing vector
            base_idx = random.randint(0, self.size - 1)
            base_vector, _ = self.retrieve_vector(base_idx)
            
            # Generate a noise vector with controlled similarity
            similarity = random.uniform(similarity_range[0], similarity_range[1])
            noise_vector = np.random.randn(self.dimensions)
            
            # Normalize the noise vector
            noise_vector = noise_vector / np.linalg.norm(noise_vector)
            
            # Mix base vector and noise to achieve desired similarity
            mixed_vector = similarity * base_vector + (1 - similarity) * noise_vector
            
            # Normalize
            mixed_vector = mixed_vector / np.linalg.norm(mixed_vector)
            
            # Add to database with noise metadata
            noise_metadata = {
                'type': 'noise',
                'base_vector': base_idx,
                'similarity': similarity
            }
            
            idx = self.add_vector(mixed_vector, noise_metadata)
            indices.append(idx)
        
        return indices
    
    def create_secure_backup(
        self, 
        backup_filename: str,
        encryption_password: str,
        split_shares: int = 3,
        threshold_shares: int = 2
    ) -> Dict[str, Any]:
        """
        Create a secure backup of the database with maximum security
        
        Args:
            backup_filename: Filename for the backup
            encryption_password: Password for encryption
            split_shares: Number of shares to split the file into
            threshold_shares: Minimum number of shares needed to reconstruct
            
        Returns:
            Dictionary with backup information
        """
        # First, add some noise vectors for obfuscation
        noise_count = max(50, int(self.size * 0.1))  # 10% of db size or at least 50
        noise_indices = self.add_noise_vectors(noise_count)
        
        # Save with all security features enabled
        backup_info = self.save_secure(
            filename=backup_filename,
            split_shares=split_shares,
            threshold_shares=threshold_shares,
            encryption_password=encryption_password,
            add_statistical_noise=True,
            sign_data=True
        )
        
        # Add backup-specific information
        backup_info.update({
            'backup_creation_time': str(datetime.datetime.now()),
            'noise_vectors_added': noise_count,
            'recovery_command': (
                f"python vbsks.py db secure-load "
                f"--recovery-info {backup_filename}.recovery_info "
                f"--encryption-password [YOUR-PASSWORD]"
            )
        })
        
        return backup_info 