#!/usr/bin/env python3
"""
High Security Setup Example

This example demonstrates how to configure VBSKS for maximum security,
suitable for government agencies and high-security applications.
"""

import os
import sys
import base64
import getpass
import json
import numpy as np
from pathlib import Path

# Add parent directory to path for imports when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import VBSKS modules
from vbsks_easy import VBSKSEasy
from vector_db import VectorDatabase
from key_manager import QuantumResistantKeyManager
from secure_storage import SecureStorage

# High security parameters
HIGH_SECURITY_PARAMS = {
    "dimensions": 256,           # Higher dimensions for increased security
    "db_size": 50000,            # Larger database for more noise
    "key_length": 12,            # More vectors per key for increased security
    "threshold": 1e-8,           # Tighter threshold for vector comparison
    "statistical_noise": True,   # Add statistical noise to databases
    "shares": 5,                 # Number of shares for secret splitting
    "threshold_shares": 3,       # Minimum shares needed for reconstruction
    "pbkdf2_iterations": 600000  # High iteration count for password derivation
}

def initialize_high_security_db(db_folder):
    """Initialize a high-security vector database"""
    # Create folder if it doesn't exist
    os.makedirs(db_folder, exist_ok=True)
    
    print(f"Initializing high-security database in {db_folder}")
    print(f"Dimensions: {HIGH_SECURITY_PARAMS['dimensions']}")
    print(f"Database size: {HIGH_SECURITY_PARAMS['db_size']}")
    print(f"Key length: {HIGH_SECURITY_PARAMS['key_length']}")
    
    # Create the vector database with high-security parameters
    vector_db = VectorDatabase(
        dimensions=HIGH_SECURITY_PARAMS['dimensions'],
        size=HIGH_SECURITY_PARAMS['db_size'],
        threshold=HIGH_SECURITY_PARAMS['threshold'],
        use_indexing=True
    )
    
    # Save the database
    db_path = os.path.join(db_folder, "high_security_db.json")
    vector_db.save(db_path)
    
    print(f"Vector database initialized and saved to {db_path}")
    return vector_db, db_path

def create_secure_key_manager(vector_db, master_password):
    """Create a key manager with high-security settings"""
    # Create the key manager
    key_manager = QuantumResistantKeyManager(
        vector_db=vector_db,
        key_length=HIGH_SECURITY_PARAMS['key_length'],
        threshold=HIGH_SECURITY_PARAMS['threshold'],
        enable_reconfiguration=True,
        reconfiguration_interval=14400,  # 4 hours
        reconfiguration_password=master_password,
        pbkdf2_iterations=HIGH_SECURITY_PARAMS['pbkdf2_iterations']
    )
    
    print("Created quantum-resistant key manager with high-security settings")
    print(f"PBKDF2 iterations: {HIGH_SECURITY_PARAMS['pbkdf2_iterations']}")
    print(f"Reconfiguration interval: 4 hours")
    
    return key_manager

def store_high_security_key(vector_db, key_manager, db_folder, master_password):
    """Store a key with maximum security settings"""
    # Create secure storage
    secure_storage = SecureStorage()
    
    # Generate a random key
    key_data = os.urandom(32)  # 256-bit key
    key_id = "high_security_key"
    
    print(f"\nGenerating high-security key '{key_id}'...")
    
    # Generate key vectors and positions
    key_vectors, positions = key_manager.generate_key(key_data)
    
    print(f"Generated key with {len(positions)} vectors")
    
    # Metadata for the key
    metadata = {
        "key_id": key_id,
        "description": "High-security demonstration key",
        "security_level": "TOP_SECRET",
        "created_at": "2023-10-15T12:00:00Z"
    }
    
    # Save key with secure storage and multiple security layers
    key_file = os.path.join(db_folder, f"{key_id}.key")
    
    print(f"\nSaving key with multiple security layers...")
    
    # First layer: Key file with encryption and digital signature
    key_manager.save_key_data_secure(
        filename=key_file,
        key_vectors=key_vectors,
        positions=positions,
        metadata=metadata,
        encryption_password=master_password,
        sign_data=True,
        save_map=True
    )
    
    print(f"Primary key file saved: {key_file}")
    
    # Second layer: Split into shares
    shares_folder = os.path.join(db_folder, "shares")
    os.makedirs(shares_folder, exist_ok=True)
    
    recovery_file = os.path.join(shares_folder, f"{key_id}_recovery.json")
    shares = []
    
    for i in range(HIGH_SECURITY_PARAMS['shares']):
        share_file = os.path.join(shares_folder, f"{key_id}_share_{i+1}.bin")
        shares.append(share_file)
    
    # Store with shares
    secure_storage.secure_save_vector_db(
        vector_db=vector_db,
        filename=os.path.join(db_folder, f"{key_id}_db.json"),
        split_shares=HIGH_SECURITY_PARAMS['shares'],
        share_files=shares,
        threshold_shares=HIGH_SECURITY_PARAMS['threshold_shares'],
        recovery_info_file=recovery_file,
        encryption_password=master_password,
        add_statistical_noise=HIGH_SECURITY_PARAMS['statistical_noise'],
        sign_data=True
    )
    
    print(f"Database saved with {HIGH_SECURITY_PARAMS['shares']} shares (threshold: {HIGH_SECURITY_PARAMS['threshold_shares']})")
    print(f"Recovery file: {recovery_file}")
    print(f"Share files stored in: {shares_folder}")
    
    # Third layer: Backup encrypted database
    backup_folder = os.path.join(db_folder, "backup")
    os.makedirs(backup_folder, exist_ok=True)
    
    backup_file = os.path.join(backup_folder, f"{key_id}_backup.enc")
    
    # Get a different password for the backup
    backup_password = getpass.getpass("\nEnter a separate backup password: ")
    
    # Save encrypted backup
    backup_db = vector_db.save_secure(
        filename=backup_file,
        encryption_password=backup_password,
        add_statistical_noise=True,
        sign_data=True
    )
    
    print(f"Encrypted backup saved: {backup_file}")
    
    return key_id, positions, key_vectors

def retrieve_high_security_key(vector_db, key_manager, db_folder, master_password, key_id, positions=None):
    """Retrieve a key with various security mechanisms"""
    if positions is None:
        # In a real application, you would need to load the positions from a secure source
        key_map_file = os.path.join(db_folder, "high_security_map.json")
        if os.path.exists(key_map_file):
            with open(key_map_file, 'r') as f:
                key_map = json.load(f)
                positions = key_map.get(key_id, {}).get('positions')
    
    if not positions:
        print(f"Error: No positions found for key '{key_id}'")
        return None
    
    print(f"\nRetrieving high-security key '{key_id}'...")
    
    # Retrieve key vectors from the database
    key_vectors = key_manager.retrieve_key(positions)
    
    # Verify the key
    is_valid = key_manager.verify_key(positions, key_vectors)
    
    if not is_valid:
        print("Error: Key verification failed!")
        return None
    
    print("Key vectors successfully retrieved and verified")
    
    # Derive cryptographic key
    crypto_key = key_manager.derive_cryptographic_key(key_vectors)
    
    print(f"Derived cryptographic key (hex): {crypto_key.hex()}")
    
    # Display options for key usage
    print("\nHigh-security key retrieval completed. This key can now be used for:")
    print("1. Post-quantum encryption")
    print("2. Digital signatures")
    print("3. Authentication")
    print("4. Other cryptographic operations")
    
    return crypto_key

def demonstrate_recovery(db_folder, key_id, master_password):
    """Demonstrate recovery with shares"""
    shares_folder = os.path.join(db_folder, "shares")
    recovery_file = os.path.join(shares_folder, f"{key_id}_recovery.json")
    
    if not os.path.exists(recovery_file):
        print(f"Error: Recovery file not found: {recovery_file}")
        return False
    
    print("\nDemonstrating recovery with shares...")
    
    # Create secure storage
    secure_storage = SecureStorage()
    
    # Get available share files
    share_files = []
    for i in range(1, HIGH_SECURITY_PARAMS['shares'] + 1):
        share_file = os.path.join(shares_folder, f"{key_id}_share_{i}.bin")
        if os.path.exists(share_file):
            share_files.append(share_file)
    
    threshold = HIGH_SECURITY_PARAMS['threshold_shares']
    print(f"Found {len(share_files)} share files (threshold: {threshold})")
    
    if len(share_files) < threshold:
        print(f"Error: Not enough shares for recovery. Need at least {threshold}.")
        return False
    
    # Use only the threshold number of shares for demonstration
    selected_shares = share_files[:threshold]
    print(f"Using {len(selected_shares)} shares for recovery")
    
    try:
        # Load database using the recovery info and shares
        recovered_db, info = secure_storage.secure_load_vector_db(
            recovery_info_file=recovery_file,
            share_files=selected_shares,
            encryption_password=master_password
        )
        
        print("\nDatabase successfully recovered from shares!")
        print(f"Dimensions: {recovered_db.dimensions}")
        print(f"Size: {recovered_db.size}")
        
        return True
    except Exception as e:
        print(f"Error during recovery: {str(e)}")
        return False

def main():
    """Main function demonstrating high-security setup"""
    print("VBSKS High-Security Setup Demo")
    print("==============================\n")
    
    # Create a secure database folder
    db_folder = os.path.join(os.path.dirname(__file__), "high_security_data")
    
    # Get master password
    master_password = getpass.getpass("Enter master password for high-security operations: ")
    confirm_password = getpass.getpass("Confirm master password: ")
    
    if master_password != confirm_password:
        print("Error: Passwords do not match!")
        return
    
    # Step 1: Initialize high-security database
    vector_db, db_path = initialize_high_security_db(db_folder)
    
    # Step 2: Create secure key manager
    key_manager = create_secure_key_manager(vector_db, master_password)
    
    # Step 3: Store a high-security key
    key_id, positions, key_vectors = store_high_security_key(
        vector_db, key_manager, db_folder, master_password
    )
    
    # Save positions to key map for demonstration purposes
    # In a real system, this would be protected with additional security
    key_map_file = os.path.join(db_folder, "high_security_map.json")
    
    with open(key_map_file, 'w') as f:
        json.dump({key_id: {"positions": positions}}, f, indent=2)
    
    print(f"\nSaved key positions to: {key_map_file}")
    print("IMPORTANT: In a real high-security environment, positions should be stored securely!")
    
    # Step 4: Retrieve the high-security key
    crypto_key = retrieve_high_security_key(
        vector_db, key_manager, db_folder, master_password, key_id, positions
    )
    
    if crypto_key is None:
        print("Error retrieving key.")
        return
    
    # Step 5: Demonstrate share-based recovery
    success = demonstrate_recovery(db_folder, key_id, master_password)
    
    if success:
        print("\nHigh-security demonstration completed successfully!")
        print("This example demonstrated multiple security layers including:")
        print("- High-dimensional vector space (256D)")
        print("- Longer key vectors (12 vectors per key)")
        print("- Shamir's Secret Sharing with 5 shares (threshold: 3)")
        print("- Statistical noise addition")
        print("- Password-based encryption")
        print("- Digital signatures")
        print("- Secure backup mechanisms")
    else:
        print("\nRecovery demonstration failed.")

if __name__ == "__main__":
    main() 