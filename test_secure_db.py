#!/usr/bin/env python3
"""
Test script for verifying secure database functionality

This script demonstrates:
1. Creating a vector database
2. Adding test key vectors
3. Saving the database with various security configurations
4. Loading the secured database
5. Verifying the loaded database is functionally identical to the original
"""

import os
import numpy as np
import json
import base64
from pathlib import Path

from vector_db import VectorDatabase
from key_manager import KeyManager
from secure_storage import SecureStorage

# Use a more relaxed threshold for comparing vectors after obfuscation
# The obfuscation process introduces small numerical differences
COMPARISON_THRESHOLD = 0.001

def test_secure_db_basic():
    """Test basic secure database save and load"""
    print("\n=== Testing Basic Secure Database Functionality ===")
    
    # Create a small test database
    print("Creating test database...")
    db = VectorDatabase(dimensions=20, size=100, threshold=1e-6)
    
    # Add some test vectors at known positions
    test_positions = [10, 20, 30, 40, 50]
    test_vectors = []
    
    print("Adding test vectors at known positions...")
    for i, pos in enumerate(test_positions):
        # Create a recognizable test vector
        vector = np.zeros(db.dimensions)
        vector[0] = i + 1  # Make each vector unique and recognizable
        vector[1] = 42.0   # Common value for easy identification
        
        # Store the vector
        db.store_vector(pos, vector)
        test_vectors.append(vector)
    
    # Save with basic secure configuration
    print("Saving database with basic secure configuration...")
    secure_filename = "test_db_secure.json"
    result = db.save_secure(
        filename=secure_filename,
        use_quantum_resistant=True,
        split_shares=1,
        threshold=1,
        encryption_password=None,
        obfuscate=True
    )
    
    print(f"Secure file saved: {result['files']['main']}")
    
    # Load the secure database
    print("Loading secure database...")
    loaded_db = VectorDatabase.load_secure(
        source=secure_filename,
        encryption_password=None,
        deobfuscate=True
    )
    
    # Verify the loaded database has the same test vectors
    print("Verifying retrieved vectors...")
    all_match = True
    for i, pos in enumerate(test_positions):
        original_vector = test_vectors[i]
        loaded_vector = loaded_db.retrieve_vector(pos)
        
        # Check if they match within threshold
        distance = np.sqrt(np.sum((original_vector - loaded_vector)**2))
        match = distance <= COMPARISON_THRESHOLD
        
        print(f"  Position {pos}: {'MATCH' if match else 'MISMATCH'} (distance: {distance:.8f})")
        if not match:
            all_match = False
    
    if all_match:
        print("SUCCESS: All vectors match!")
    else:
        print("FAILURE: Some vectors don't match!")
    
    return all_match

def test_secure_db_with_shares():
    """Test database with share splitting"""
    print("\n=== Testing Secure Database with Share Splitting ===")
    
    # Create a small test database
    print("Creating test database...")
    db = VectorDatabase(dimensions=20, size=100, threshold=1e-6)
    
    # Add some test vectors at known positions
    test_positions = [15, 25, 35, 45, 55]
    test_vectors = []
    
    print("Adding test vectors at known positions...")
    for i, pos in enumerate(test_positions):
        # Create a recognizable test vector
        vector = np.zeros(db.dimensions)
        vector[0] = i + 10  # Make each vector unique and recognizable
        vector[1] = 99.0    # Common value for easy identification
        
        # Store the vector
        db.store_vector(pos, vector)
        test_vectors.append(vector)
    
    # Save with share splitting
    print("Saving database with share splitting (5 shares, threshold 3)...")
    secure_filename = "test_db_shares.json"
    result = db.save_secure(
        filename=secure_filename,
        use_quantum_resistant=True,
        split_shares=5,
        threshold=3,
        encryption_password=None,
        obfuscate=True
    )
    
    print("Share files created:")
    share_files = []
    for key, file in result['files'].items():
        if key.startswith('share_'):
            print(f"  {file}")
            share_files.append(file)
    
    recovery_info = result['files'].get('recovery_info')
    print(f"Recovery info: {recovery_info}")
    
    # Test loading from recovery info
    print("\nLoading database using recovery info...")
    loaded_db_1 = VectorDatabase.load_secure(
        source=recovery_info,
        encryption_password=None,
        deobfuscate=True
    )
    
    # Verify loaded database 1
    print("Verifying vectors from recovery info load...")
    recovery_load_success = True
    for i, pos in enumerate(test_positions):
        original_vector = test_vectors[i]
        loaded_vector = loaded_db_1.retrieve_vector(pos)
        
        # Check if they match within threshold
        distance = np.sqrt(np.sum((original_vector - loaded_vector)**2))
        match = distance <= COMPARISON_THRESHOLD
        
        print(f"  Position {pos}: {'MATCH' if match else 'MISMATCH'} (distance: {distance:.8f})")
        if not match:
            recovery_load_success = False
    
    if recovery_load_success:
        print("SUCCESS: Recovery info load successful!")
    else:
        print("FAILURE: Recovery info load failed!")
    
    # Test loading from minimum shares (exactly the threshold)
    print("\nLoading database using minimum required shares (3 of 5)...")
    min_shares = share_files[:3]  # Take just 3 shares
    loaded_db_2 = VectorDatabase.load_secure(
        source=min_shares,
        encryption_password=None,
        deobfuscate=True
    )
    
    # Verify loaded database 2
    print("Verifying vectors from minimum shares load...")
    min_shares_success = True
    for i, pos in enumerate(test_positions):
        original_vector = test_vectors[i]
        loaded_vector = loaded_db_2.retrieve_vector(pos)
        
        # Check if they match within threshold
        distance = np.sqrt(np.sum((original_vector - loaded_vector)**2))
        match = distance <= COMPARISON_THRESHOLD
        
        print(f"  Position {pos}: {'MATCH' if match else 'MISMATCH'} (distance: {distance:.8f})")
        if not match:
            min_shares_success = False
    
    if min_shares_success:
        print("SUCCESS: Minimum shares load successful!")
    else:
        print("FAILURE: Minimum shares load failed!")
    
    # Test loading with insufficient shares
    print("\nTesting load with insufficient shares (2 of 5, threshold is 3)...")
    insufficient_shares = share_files[:2]  # Take just 2 shares
    try:
        loaded_db_3 = VectorDatabase.load_secure(
            source=insufficient_shares,
            encryption_password=None,
            deobfuscate=True
        )
        print("FAILURE: Load succeeded but should have failed!")
        insufficient_shares_test = False
    except ValueError as e:
        print(f"SUCCESS: Load failed as expected: {str(e)}")
        insufficient_shares_test = True
    
    return recovery_load_success and min_shares_success and insufficient_shares_test

def test_secure_db_with_password():
    """Test database with password protection"""
    print("\n=== Testing Secure Database with Password Protection ===")
    
    # Create a small test database
    print("Creating test database...")
    db = VectorDatabase(dimensions=20, size=100, threshold=1e-6)
    
    # Add some test vectors at known positions
    test_positions = [5, 15, 25, 35, 45]
    test_vectors = []
    
    print("Adding test vectors at known positions...")
    for i, pos in enumerate(test_positions):
        # Create a recognizable test vector
        vector = np.zeros(db.dimensions)
        vector[0] = i + 20  # Make each vector unique and recognizable
        vector[1] = 123.0   # Common value for easy identification
        
        # Store the vector
        db.store_vector(pos, vector)
        test_vectors.append(vector)
    
    # Save with password protection
    test_password = "secure-password-123"
    print(f"Saving database with password protection...")
    secure_filename = "test_db_password.json"
    result = db.save_secure(
        filename=secure_filename,
        use_quantum_resistant=True,
        split_shares=1,
        threshold=1,
        encryption_password=test_password,
        obfuscate=True
    )
    
    print(f"Secure file saved: {result['files']['main']}")
    
    # Load with correct password
    print("\nLoading database with correct password...")
    try:
        loaded_db_1 = VectorDatabase.load_secure(
            source=secure_filename,
            encryption_password=test_password,
            deobfuscate=True
        )
        print("SUCCESS: Load with correct password succeeded!")
        correct_password_success = True
    except Exception as e:
        print(f"FAILURE: Load with correct password failed: {str(e)}")
        correct_password_success = False
    
    # Verify loaded database
    if correct_password_success:
        print("Verifying vectors from password-protected database...")
        all_match = True
        for i, pos in enumerate(test_positions):
            original_vector = test_vectors[i]
            loaded_vector = loaded_db_1.retrieve_vector(pos)
            
            # Check if they match within threshold
            distance = np.sqrt(np.sum((original_vector - loaded_vector)**2))
            match = distance <= COMPARISON_THRESHOLD
            
            print(f"  Position {pos}: {'MATCH' if match else 'MISMATCH'} (distance: {distance:.8f})")
            if not match:
                all_match = False
        
        if all_match:
            print("SUCCESS: All vectors match!")
        else:
            print("FAILURE: Some vectors don't match!")
            correct_password_success = False
    
    # Try loading with incorrect password
    print("\nTesting load with incorrect password...")
    wrong_password = "wrong-password-456"
    try:
        loaded_db_2 = VectorDatabase.load_secure(
            source=secure_filename,
            encryption_password=wrong_password,
            deobfuscate=True
        )
        print("FAILURE: Load with incorrect password succeeded but should have failed!")
        wrong_password_test = False
    except Exception as e:
        print(f"SUCCESS: Load with incorrect password failed as expected: {str(e)}")
        wrong_password_test = True
    
    return correct_password_success and wrong_password_test

def test_comprehensive():
    """Test all security features combined"""
    print("\n=== Testing Comprehensive Security (All Features) ===")
    
    # Create a small test database
    print("Creating test database...")
    db = VectorDatabase(dimensions=20, size=100, threshold=1e-6)
    
    # Add some test vectors at known positions
    test_positions = [7, 17, 27, 37, 47]
    test_vectors = []
    
    print("Adding test vectors at known positions...")
    for i, pos in enumerate(test_positions):
        # Create a recognizable test vector
        vector = np.zeros(db.dimensions)
        vector[0] = i + 30  # Make each vector unique and recognizable
        vector[1] = 456.0   # Common value for easy identification
        
        # Store the vector
        db.store_vector(pos, vector)
        test_vectors.append(vector)
    
    # Save with all security features
    test_password = "ultra-secure-pwd-789"
    print(f"Saving database with all security features...")
    secure_filename = "test_db_comprehensive.json"
    result = db.save_secure(
        filename=secure_filename,
        use_quantum_resistant=True,
        split_shares=5,
        threshold=3,
        encryption_password=test_password,
        obfuscate=True
    )
    
    share_files = []
    for key, file in result['files'].items():
        if key.startswith('share_'):
            share_files.append(file)
    
    recovery_info = result['files'].get('recovery_info')
    print(f"Recovery info: {recovery_info}")
    print(f"Created {len(share_files)} share files (threshold: 3)")
    
    # Load with all security features
    print("\nLoading database with recovery info and password...")
    try:
        loaded_db = VectorDatabase.load_secure(
            source=recovery_info,
            encryption_password=test_password,
            deobfuscate=True
        )
        print("SUCCESS: Load with all security features succeeded!")
        load_success = True
    except Exception as e:
        print(f"FAILURE: Load with all security features failed: {str(e)}")
        load_success = False
    
    # Verify loaded database
    if load_success:
        print("Verifying vectors...")
        all_match = True
        for i, pos in enumerate(test_positions):
            original_vector = test_vectors[i]
            loaded_vector = loaded_db.retrieve_vector(pos)
            
            # Check if they match within threshold
            distance = np.sqrt(np.sum((original_vector - loaded_vector)**2))
            match = distance <= COMPARISON_THRESHOLD
            
            print(f"  Position {pos}: {'MATCH' if match else 'MISMATCH'} (distance: {distance:.8f})")
            if not match:
                all_match = False
        
        if all_match:
            print("SUCCESS: All vectors match!")
        else:
            print("FAILURE: Some vectors don't match!")
            load_success = False
    
    return load_success

def cleanup():
    """Clean up test files"""
    print("\n=== Cleaning up test files ===")
    test_files = [
        "test_db_secure.json",
        "test_db_shares.json*",
        "test_db_password.json",
        "test_db_comprehensive.json*"
    ]
    
    for pattern in test_files:
        for file in Path('.').glob(pattern):
            print(f"Removing {file}...")
            file.unlink()

def main():
    """Run all tests"""
    try:
        # Run all tests
        basic_test = test_secure_db_basic()
        shares_test = test_secure_db_with_shares()
        password_test = test_secure_db_with_password()
        comprehensive_test = test_comprehensive()
        
        # Print summary
        print("\n=== Test Summary ===")
        print(f"Basic Secure Database:         {'PASSED' if basic_test else 'FAILED'}")
        print(f"Database with Share Splitting: {'PASSED' if shares_test else 'FAILED'}")
        print(f"Database with Password:        {'PASSED' if password_test else 'FAILED'}")
        print(f"Comprehensive Security:        {'PASSED' if comprehensive_test else 'FAILED'}")
        
        all_passed = basic_test and shares_test and password_test and comprehensive_test
        print(f"\nOverall Test Result: {'ALL TESTS PASSED!' if all_passed else 'SOME TESTS FAILED'}")
        
        # Clean up test files
        cleanup()
        
        return 0 if all_passed else 1
    except Exception as e:
        print(f"\nTest failure: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main()) 