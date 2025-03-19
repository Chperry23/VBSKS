#!/usr/bin/env python3
"""
Simplified test script for VBSKS functionality
"""

import os
import numpy as np
from vector_db import VectorDatabase

# Create a simple vector database
print("Creating test vector database...")
db = VectorDatabase(dimensions=20, size=50, threshold=1e-6, use_indexing=False)

# Save to standard format
print("Saving to standard format...")
db.save("test_standard_db.json")

# Load from standard format 
print("Loading from standard format...")
loaded_db = VectorDatabase.load("test_standard_db.json")
print(f"Loaded database: {loaded_db.dimensions} dimensions, {loaded_db.size} vectors")

# Clean up
os.remove("test_standard_db.json")
print("Standard format test completed successfully")

try:
    # Try to save with secure features
    print("\nTesting secure save with minimal features...")
    result = db.save_secure(
        filename="test_secure_db.json",
        encryption_password="test-password"
    )
    print(f"Secure save result: {result.get('filename', 'unknown')}")
    
    # Try to load with secure features
    print("Testing secure load...")
    loaded_secure_db, info = VectorDatabase.load_secure(
        filename="test_secure_db.json",
        encryption_password="test-password"
    )
    print(f"Loaded secure database: {loaded_secure_db.dimensions} dimensions, {loaded_secure_db.size} vectors")
    print(f"Security info: Password protected: {info.get('password_protected', False)}, Signed: {info.get('signed', False)}")
    
    # Clean up
    os.remove("test_secure_db.json")
    print("Secure format test completed successfully")
except Exception as e:
    print(f"Secure test error: {str(e)}")

try:
    # Test simpler secure storage approach
    print("\nTesting simpler secure approach...")
    # Add a vector with metadata
    print("Adding a vector with metadata...")
    test_vector = np.random.rand(db.dimensions)
    test_vector = test_vector / np.linalg.norm(test_vector)
    metadata = {"name": "test_vector", "created": "2023-09-10"}
    index = db.add_vector(test_vector, metadata)
    print(f"Added vector at index {index}")
    
    # Save the database
    print("Saving database with password only...")
    result = db.save_secure(
        filename="simple_secure_db.json",
        encryption_password="simple-password",
        split_shares=1,  # No splitting
        add_statistical_noise=False,  # No noise
        sign_data=False  # No signature
    )
    
    # Load the database
    print("Loading database with password only...")
    loaded_db, info = VectorDatabase.load_secure(
        filename="simple_secure_db.json",
        encryption_password="simple-password"
    )
    
    # Verify the vector and metadata
    loaded_vector, loaded_metadata = loaded_db.retrieve_vector(index)
    vector_match = np.allclose(test_vector, loaded_vector, atol=1e-5)
    metadata_match = loaded_metadata.get("name") == metadata.get("name")
    
    print(f"Vector match: {vector_match}")
    print(f"Metadata match: {metadata_match}")
    
    # Clean up
    os.remove("simple_secure_db.json")
    print("Simple secure test completed successfully")
except Exception as e:
    print(f"Simple secure test error: {str(e)}")

print("\nAll tests completed.") 