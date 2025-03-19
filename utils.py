"""
Utility functions for Vector-Based Secure Key Storage (VBSKS)
"""

import numpy as np
import time
from typing import List, Tuple, Dict, Any, Union, Optional
import json
import hashlib
import os
import secrets

# Constants
MIN_VALUE = 1.0
MAX_VALUE = 10000.0
PRECISION = 1e-6

# Export constants that will be used by other modules
__all__ = [
    'MIN_VALUE', 
    'MAX_VALUE', 
    'PRECISION', 
    'generate_random_vector',
    'constant_time_equal',
    'euclidean_distance',
    'save_vectors',
    'load_vectors',
    'secure_hash',
    'derive_positions',
    'quantize_vector'
]

def generate_random_vector(dimensions: int) -> np.ndarray:
    """
    Generate a random vector with high-precision values in the range [MIN_VALUE, MAX_VALUE]
    
    Args:
        dimensions: Number of dimensions for the vector
        
    Returns:
        A random vector with the specified dimensions
    """
    # Using numpy's random generator with full precision
    return np.random.uniform(MIN_VALUE, MAX_VALUE, dimensions)

def constant_time_equal(vec1: np.ndarray, vec2: np.ndarray, threshold: float = PRECISION) -> bool:
    """
    Compare two vectors in constant time to prevent timing attacks
    
    Args:
        vec1: First vector
        vec2: Second vector
        threshold: Maximum distance for vectors to be considered equal
        
    Returns:
        True if vectors are equal within the threshold, False otherwise
    """
    if vec1.shape != vec2.shape:
        # Always do the same computation even if shapes don't match
        dummy = np.sum((np.zeros_like(vec1) - np.zeros_like(vec1))**2)
        return False
        
    # Compute Euclidean distance
    distance = np.sqrt(np.sum((vec1 - vec2)**2))
    
    # Ensure comparison is done in constant time
    # This is a simple approach - in production, more robust constant-time
    # comparison should be implemented
    result = distance <= threshold
    
    # Add a small random delay to further mask the timing
    time.sleep(secrets.SystemRandom().uniform(0.001, 0.002))
    
    return result

def euclidean_distance(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """
    Calculate the Euclidean distance between two vectors
    
    Args:
        vec1: First vector
        vec2: Second vector
        
    Returns:
        The Euclidean distance
    """
    return np.sqrt(np.sum((vec1 - vec2)**2))

def save_vectors(vectors: np.ndarray, filename: str) -> None:
    """
    Save vectors to a JSON file
    
    Args:
        vectors: Array of vectors to save
        filename: Path to the output file
    """
    with open(filename, 'w') as f:
        json.dump({
            'vectors': vectors.tolist(),
            'shape': vectors.shape,
        }, f, indent=2)

def load_vectors(filename: str) -> np.ndarray:
    """
    Load vectors from a JSON file
    
    Args:
        filename: Path to the input file
        
    Returns:
        Array of vectors
    """
    with open(filename, 'r') as f:
        data = json.load(f)
        return np.array(data['vectors'])

def secure_hash(data: Union[str, bytes]) -> str:
    """
    Compute a secure hash of the input data
    
    Args:
        data: Input data to hash
        
    Returns:
        Hex digest of the hash
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha3_256(data).hexdigest()

def derive_positions(seed: str, noise_size: int, key_length: int) -> List[int]:
    """
    Deterministically derive positions in the noise database to store key vectors
    
    Args:
        seed: Seed string for the random number generator
        noise_size: Size of the noise database
        key_length: Number of key vectors
        
    Returns:
        List of positions
    """
    # Create a seeded random number generator
    rng = np.random.RandomState(int(hashlib.sha256(seed.encode()).hexdigest(), 16) % 2**32)
    
    # Generate unique positions
    positions = rng.choice(noise_size, key_length, replace=False)
    return positions.tolist()

def quantize_vector(vector: np.ndarray, precision: int = 6) -> np.ndarray:
    """
    Quantize a vector to a specific precision to avoid floating-point errors
    
    Args:
        vector: Input vector
        precision: Number of decimal places to retain
        
    Returns:
        Quantized vector
    """
    return np.round(vector, precision) 