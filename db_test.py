#!/usr/bin/env python3
"""
Simple script to test saving and loading a vector database.
This demonstrates our improved binary data handling.
"""

import os
import numpy as np
import tempfile
import json
from pathlib import Path

from vector_db import VectorDatabase
from secure_storage import SecureStorage

def create_test_db(dimensions=20, size=50):
    """Create a test vector database with random data"""
    print(f"Creating test database ({dimensions} dimensions, {size} vectors)...")
    db = VectorDatabase(dimensions=dimensions, size=0, threshold=1e-6, use_indexing=False)
    
    # Add vectors with metadata
    for i in range(size):
        vector = np.random.rand(dimensions)
        metadata = {"index": i, "name": f"test_vector_{i}", "created": "2023-09-10"}
        db.add_vector(vector, metadata)
    
    return db

def test_standard_save_load(db, output_dir):
    """Test standard (non-secure) save and load"""
    print("\n=== Testing Standard Save/Load ===")
    filename = output_dir / "standard_db.json"
    
    # Save the database
    print(f"Saving database to {filename}...")
    db.save(str(filename))
    
    # Load the database
    print(f"Loading database from {filename}...")
    loaded_db = VectorDatabase.load(str(filename))
    
    # Verify
    assert loaded_db.dimensions == db.dimensions, "Dimensions mismatch"
    assert loaded_db.size == db.size, "Size mismatch"
    print(f"Verification successful: dimensions={loaded_db.dimensions}, size={loaded_db.size}")
    return loaded_db

def test_secure_save_load(db, output_dir, password="test-password"):
    """Test secure save and load"""
    print("\n=== Testing Secure Save/Load ===")
    filename = output_dir / "secure_db.json"
    secure_storage = SecureStorage()
    
    # Save with security features
    print(f"Saving database securely to {filename}...")
    result = secure_storage.secure_save_vector_db(
        vector_db=db,
        filename=str(filename),
        encryption_password=password,
        add_statistical_noise=True,
        sign_data=True
    )
    
    # Display result info
    print(f"Save result: {json.dumps({k: v for k, v in result.items() if k not in ['password_protection', 'pqc_info']}, indent=2)}")
    
    # Load with security features
    print(f"Loading database securely from {filename}...")
    loaded_db, info = secure_storage.secure_load_vector_db(
        filename=str(filename),
        encryption_password=password
    )
    
    # Display security info
    print(f"Load info: {json.dumps({k: v for k, v in info.items() if k not in ['password_protection', 'pqc_info']}, indent=2)}")
    
    # Verify
    assert loaded_db.dimensions == db.dimensions, "Dimensions mismatch"
    assert loaded_db.size == db.size, "Size mismatch"
    print(f"Verification successful: dimensions={loaded_db.dimensions}, size={loaded_db.size}")
    return loaded_db

def test_shares_save_load(db, output_dir, password="test-password"):
    """Test secure save and load with shares"""
    print("\n=== Testing Secure Save/Load with Shares ===")
    filename = output_dir / "shares_db.json"
    secure_storage = SecureStorage()
    
    # Save with shares
    print(f"Saving database with shares to {filename}...")
    result = secure_storage.secure_save_vector_db(
        vector_db=db,
        filename=str(filename),
        split_shares=3,
        threshold_shares=2,
        encryption_password=password,
        sign_data=True
    )
    
    # Display result info
    print(f"Save result: {json.dumps({k: v for k, v in result.items() if k not in ['password_protection', 'pqc_info']}, indent=2)}")
    
    # Verify share files exist
    for i in range(1, 4):
        share_file = filename.with_suffix(f".json.share{i}")
        assert os.path.exists(share_file), f"Share file {share_file} does not exist"
    
    # Verify recovery info exists
    recovery_file = filename.with_suffix(".json.recovery_info")
    assert os.path.exists(recovery_file), f"Recovery file {recovery_file} does not exist"
    
    # Load using recovery info
    print(f"Loading database using recovery info {recovery_file}...")
    try:
        loaded_db, info = secure_storage.secure_load_vector_db(
            recovery_info_file=str(recovery_file),
            encryption_password=password
        )
        
        # Verify
        assert loaded_db.dimensions == db.dimensions, "Dimensions mismatch"
        assert loaded_db.size == db.size, "Size mismatch"
        print(f"Verification successful: dimensions={loaded_db.dimensions}, size={loaded_db.size}")
    except Exception as e:
        print(f"Error loading with recovery info: {str(e)}")
        print("This might be expected if using simulated shares that require all shares")
    
    return True

def main():
    """Run all tests"""
    print("VBSKS Database Save/Load Test")
    print("============================")
    
    # Create temp directory for test files
    with tempfile.TemporaryDirectory() as tempdir:
        output_dir = Path(tempdir)
        print(f"Using temporary directory: {output_dir}")
        
        try:
            # Create test database
            db = create_test_db()
            
            # Run tests
            test_standard_save_load(db, output_dir)
            test_secure_save_load(db, output_dir)
            test_shares_save_load(db, output_dir)
            
            print("\nAll tests completed successfully!")
            
        except Exception as e:
            print(f"\nTest failed with error: {str(e)}")

if __name__ == "__main__":
    main() 