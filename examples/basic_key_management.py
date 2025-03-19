#!/usr/bin/env python3
"""
Basic Key Management Example

This example demonstrates how to use VBSKS for basic key storage and retrieval.
"""

import os
import sys
import base64
import getpass

# Add parent directory to path for imports when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import VBSKS modules
from vbsks_easy import VBSKSEasy

def main():
    """Main function demonstrating basic VBSKS operations"""
    print("VBSKS Basic Key Management Example")
    print("==================================\n")
    
    # Initialize VBSKS with a custom folder
    db_folder = os.path.join(os.path.dirname(__file__), "basic_example_data")
    vbsks = VBSKSEasy(
        db_folder=db_folder,
        auto_reconfigure=True,
        dimensions=100,
        db_size=5000,  # Smaller DB for example purposes
        key_length=8
    )
    
    print(f"Initialized VBSKS in folder: {db_folder}")
    
    # Get master password for operations
    master_password = getpass.getpass("\nEnter master password: ")
    
    # Part 1: Store a new key
    print("\n1. Storing a new key...")
    key_id = "example_key_1"
    secret_data = "This is a secret message to be stored securely"
    
    result = vbsks.store_key(
        key_id=key_id,
        master_password=master_password,
        data=secret_data,
        metadata={"description": "Example key", "usage": "demonstration"}
    )
    
    if result['status'] == 'success':
        print(f"Key '{key_id}' stored successfully")
        print(f"Key file: {result['key_file']}")
    else:
        print(f"Error storing key: {result.get('error', 'Unknown error')}")
        return
    
    # Part 2: List existing keys
    print("\n2. Listing existing keys...")
    result = vbsks.list_keys()
    
    if result['status'] == 'success':
        keys = result['keys']
        print(f"Found {len(keys)} keys:")
        
        for key_id, info in keys.items():
            print(f"\n  Key ID: {key_id}")
            
            if 'metadata' in info:
                metadata = info['metadata']
                if 'description' in metadata:
                    print(f"  Description: {metadata['description']}")
                if 'usage' in metadata:
                    print(f"  Usage: {metadata['usage']}")
    else:
        print(f"Error listing keys: {result.get('error', 'Unknown error')}")
    
    # Part 3: Retrieve a key
    print("\n3. Retrieving key...")
    result = vbsks.retrieve_key(
        key_id=key_id,
        master_password=master_password
    )
    
    if result['status'] == 'success':
        print(f"Key '{key_id}' retrieved successfully")
        
        if result.get('reconfigured'):
            print("Note: Key was automatically reconfigured for enhanced security")
        
        # The crypto_key is base64 encoded, we need to decode it
        crypto_key = result['crypto_key']
        try:
            # Try to interpret as UTF-8 string (if it was text originally)
            key_bytes = base64.b64decode(crypto_key)
            key_text = key_bytes.decode('utf-8')
            print(f"\nRetrieved key value: {key_text}")
        except:
            # Otherwise just show the base64
            print(f"\nRetrieved key (base64): {crypto_key}")
    else:
        print(f"Error retrieving key: {result.get('error', 'Unknown error')}")
    
    # Part 4: Create a backup of the database
    print("\n4. Creating a backup...")
    backup_password = getpass.getpass("Enter backup password: ")
    
    result = vbsks.backup_database(backup_password)
    
    if result['status'] == 'success':
        print("Database backup created successfully")
        print(f"Backup file: {result['backup_file']}")
        print(f"Key map backup: {result['key_map_backup']}")
    else:
        print(f"Error creating backup: {result.get('error', 'Unknown error')}")
    
    # Part 5: Delete a key
    print("\n5. Deleting key...")
    result = vbsks.delete_key(key_id)
    
    if result['status'] == 'success':
        print(f"Key '{key_id}' deleted successfully")
    else:
        print(f"Error deleting key: {result.get('error', 'Unknown error')}")
    
    print("\nBasic key management operations completed.")

if __name__ == "__main__":
    main() 