#!/usr/bin/env python3
"""
Test script for the QuantumResistantKeyManager

This script tests the enhanced security features of the VBSKS system,
including quantum-resistant encryption, Shamir's secret sharing, and
password protection.
"""

import numpy as np
import os
import json
import base64
import shutil
from pathlib import Path

from vector_db import VectorDatabase
from key_manager import KeyManager, QuantumResistantKeyManager
from utils import PRECISION

# Create a test directory
TEST_DIR = Path("test_output")
TEST_DIR.mkdir(exist_ok=True)

def test_basic_functionality():
    """Test basic key generation and retrieval"""
    print("\n=== Testing Basic Functionality ===")
    
    # Create a small vector database for testing
    db = VectorDatabase(dimensions=10, size=100)
    
    # Create a quantum-resistant key manager
    qr_km = QuantumResistantKeyManager(
        vector_db=db,
        key_length=3,
        quantum_algorithm="Simulate"  # Use simulation mode for testing
    )
    
    # Generate a key
    key_vectors, positions = qr_km.generate_key("test_seed")
    
    print(f"Generated key vectors shape: {key_vectors.shape}")
    print(f"Key positions: {positions}")
    
    # Verify the key
    is_valid = qr_km.verify_key(positions, key_vectors)
    print(f"Key verification result: {is_valid}")
    
    # Derive a cryptographic key
    crypto_key = qr_km.derive_cryptographic_key(key_vectors)
    print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")
    
    return db, qr_km, key_vectors, positions

def test_secure_storage(db, qr_km, key_vectors, positions):
    """Test quantum-resistant secure storage"""
    print("\n=== Testing Quantum-Resistant Storage ===")
    
    # Save key data with quantum-resistant encryption
    qr_filename = TEST_DIR / "quantum_resistant_key.json"
    
    save_result = qr_km.save_key_data_secure(
        filename=str(qr_filename),
        key_vectors=key_vectors,
        positions=positions,
        metadata={"description": "Test quantum-resistant key"},
        use_quantum_resistant=True
    )
    
    print("Saved key data with quantum-resistant encryption:")
    print(f"  Key ID: {save_result['key_id']}")
    print(f"  Files: {list(save_result['files'].values())}")
    
    # Load the key data
    loaded_data = QuantumResistantKeyManager.load_key_data_secure(
        source=str(qr_filename)
    )
    
    # Verify the loaded data
    loaded_vectors = np.array(loaded_data['key_vectors'])
    print(f"Loaded key vectors shape: {loaded_vectors.shape}")
    print(f"Original and loaded vectors match: {np.array_equal(key_vectors, loaded_vectors)}")
    print(f"Original and loaded positions match: {positions == loaded_data['positions']}")

def test_password_protection(db, qr_km, key_vectors, positions):
    """Test password protection"""
    print("\n=== Testing Password Protection ===")
    
    # Save key data with password protection
    password_filename = TEST_DIR / "password_protected_key.json"
    password = "secure-test-password"
    
    save_result = qr_km.save_key_data_secure(
        filename=str(password_filename),
        key_vectors=key_vectors,
        positions=positions,
        metadata={"description": "Test password-protected key"},
        use_quantum_resistant=True,
        encryption_password=password
    )
    
    print("Saved key data with password protection:")
    print(f"  Key ID: {save_result['key_id']}")
    print(f"  Files: {list(save_result['files'].values())}")
    
    # Try to load without password (should fail)
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=str(password_filename)
        )
        print("ERROR: Loaded password-protected key without password!")
    except ValueError as e:
        print(f"Correctly failed to load without password: {str(e)}")
    
    # Load with correct password
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=str(password_filename),
            encryption_password=password
        )
        print("Successfully loaded with correct password.")
        loaded_vectors = np.array(loaded_data['key_vectors'])
        print(f"Original and loaded vectors match: {np.array_equal(key_vectors, loaded_vectors)}")
    except Exception as e:
        print(f"ERROR: Failed to load with correct password: {str(e)}")
    
    # Try with incorrect password
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=str(password_filename),
            encryption_password="wrong-password"
        )
        print("ERROR: Loaded with incorrect password!")
    except ValueError as e:
        print(f"Correctly failed with wrong password: {str(e)}")

def test_secret_sharing(db, qr_km, key_vectors, positions):
    """Test secret sharing (key splitting)"""
    print("\n=== Testing Secret Sharing ===")
    
    # Save key data with secret sharing
    shares_filename = TEST_DIR / "shared_key.json"
    total_shares = 5
    threshold = 3
    
    save_result = qr_km.save_key_data_secure(
        filename=str(shares_filename),
        key_vectors=key_vectors,
        positions=positions,
        metadata={"description": "Test shared key"},
        use_quantum_resistant=True,
        split_shares=total_shares,
        threshold=threshold
    )
    
    print(f"Split key into {total_shares} shares with threshold {threshold}:")
    print(f"  Key ID: {save_result['key_id']}")
    print(f"  Files: {list(save_result['files'].values())}")
    
    # Load recovery info
    recovery_file = save_result['files'].get('recovery_info')
    with open(recovery_file, 'r') as f:
        recovery_info = json.load(f)
    
    print(f"Recovery info: {recovery_info['recovery_instructions']}")
    
    # Get all share files
    share_files = [f for f in save_result['files'].values() if '.share' in f]
    
    # Try to load with fewer than threshold shares (should fail)
    insufficient_shares = share_files[:threshold-1]
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=insufficient_shares
        )
        print(f"ERROR: Loaded with insufficient shares ({len(insufficient_shares)})!")
    except ValueError as e:
        print(f"Correctly failed with insufficient shares: {str(e)}")
    
    # Try to load with exact threshold number of shares
    threshold_shares = share_files[:threshold]
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=threshold_shares
        )
        print(f"Successfully loaded with threshold number of shares ({threshold}).")
        loaded_vectors = np.array(loaded_data['key_vectors'])
        print(f"Original and loaded vectors match: {np.array_equal(key_vectors, loaded_vectors)}")
    except Exception as e:
        print(f"ERROR: Failed to load with threshold shares: {str(e)}")
    
    # Try to load with all shares
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=share_files
        )
        print(f"Successfully loaded with all shares ({len(share_files)}).")
        loaded_vectors = np.array(loaded_data['key_vectors'])
        print(f"Original and loaded vectors match: {np.array_equal(key_vectors, loaded_vectors)}")
    except Exception as e:
        print(f"ERROR: Failed to load with all shares: {str(e)}")

def test_combined_security(db, qr_km, key_vectors, positions):
    """Test all security features combined"""
    print("\n=== Testing Combined Security Features ===")
    
    # Save key data with all security features
    combined_filename = TEST_DIR / "combined_security_key.json"
    password = "very-secure-combined-password"
    total_shares = 4
    threshold = 2
    
    save_result = qr_km.save_key_data_secure(
        filename=str(combined_filename),
        key_vectors=key_vectors,
        positions=positions,
        metadata={"description": "Test combined security features"},
        use_quantum_resistant=True,
        split_shares=total_shares,
        threshold=threshold,
        encryption_password=password
    )
    
    print("Saved key with combined security features:")
    print(f"  Key ID: {save_result['key_id']}")
    print(f"  Quantum resistant: {save_result['quantum_resistant']}")
    print(f"  Password protected: {save_result['password_protected']}")
    print(f"  Shares: {save_result['shares_info']['total']} (threshold: {save_result['shares_info']['threshold']})")
    print(f"  Files: {list(save_result['files'].values())}")
    
    # Get share files
    share_files = [f for f in save_result['files'].values() if '.share' in f]
    threshold_shares = share_files[:threshold]
    
    # Try to load without password
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=threshold_shares
        )
        print("ERROR: Loaded without password!")
    except ValueError as e:
        print(f"Correctly failed without password: {str(e)}")
    
    # Try with wrong password
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=threshold_shares,
            encryption_password="wrong-password"
        )
        print("ERROR: Loaded with incorrect password!")
    except ValueError as e:
        print(f"Correctly failed with wrong password: {str(e)}")
    
    # Try with correct password but insufficient shares
    insufficient_shares = share_files[:threshold-1]
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=insufficient_shares,
            encryption_password=password
        )
        print(f"ERROR: Loaded with insufficient shares ({len(insufficient_shares)})!")
    except ValueError as e:
        print(f"Correctly failed with insufficient shares: {str(e)}")
    
    # Try with correct password and threshold shares
    try:
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=threshold_shares,
            encryption_password=password
        )
        print(f"Successfully loaded with correct password and threshold shares.")
        loaded_vectors = np.array(loaded_data['key_vectors'])
        print(f"Original and loaded vectors match: {np.array_equal(key_vectors, loaded_vectors)}")
    except Exception as e:
        print(f"ERROR: Failed to load with correct parameters: {str(e)}")

def cleanup():
    """Clean up test files"""
    print("\n=== Cleaning Up ===")
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
        print(f"Removed test directory: {TEST_DIR}")

def main():
    """Run all tests"""
    print("VBSKS Quantum-Resistant Security Tests")
    print("======================================")
    
    try:
        # Run the tests
        db, qr_km, key_vectors, positions = test_basic_functionality()
        test_secure_storage(db, qr_km, key_vectors, positions)
        test_password_protection(db, qr_km, key_vectors, positions)
        test_secret_sharing(db, qr_km, key_vectors, positions)
        test_combined_security(db, qr_km, key_vectors, positions)
        
        print("\nAll tests completed.")
    except Exception as e:
        print(f"\nTest failed with error: {str(e)}")
    finally:
        # Clean up test files
        cleanup()

if __name__ == "__main__":
    main() 