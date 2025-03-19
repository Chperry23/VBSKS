#!/usr/bin/env python3
"""
Test script focused on the share-splitting and recombination functionality in secure storage.
This will help debug issues with shares loading.
"""

import os
import json
import base64
import numpy as np
import tempfile
from pathlib import Path

from vector_db import VectorDatabase
from secure_storage import SecureStorage

def inspect_share_file(file_path):
    """Read and analyze the contents of a share file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        print(f"\nShare file: {os.path.basename(file_path)}")
        print(f"  Type: {type(data)}")
        print(f"  Keys: {', '.join(data.keys())}")
        
        if 'index' in data:
            print(f"  Index: {data['index']}")
        
        if 'share_id' in data:
            print(f"  Share ID: {data['share_id']}")
            
        if 'simulated' in data:
            print(f"  Simulated: {data['simulated']}")
            
        if 'simulated_strict' in data:
            print(f"  Simulated strict: {data['simulated_strict']}")
            
        if 'shares_info' in data:
            print(f"  Shares info: {data['shares_info']}")
            
        return data
    except Exception as e:
        print(f"Error reading share file {file_path}: {str(e)}")
        return None

def inspect_recovery_file(file_path):
    """Read and analyze the contents of a recovery info file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        print(f"\nRecovery file: {os.path.basename(file_path)}")
        print(f"  Type: {type(data)}")
        print(f"  Keys: {', '.join(data.keys())}")
        
        if 'share_files' in data:
            print(f"  Share files: {data['share_files']}")
            
        if 'total_shares' in data:
            print(f"  Total shares: {data['total_shares']}")
            
        if 'threshold_shares' in data:
            print(f"  Threshold shares: {data['threshold_shares']}")
            
        return data
    except Exception as e:
        print(f"Error reading recovery file {file_path}: {str(e)}")
        return None

def test_shares():
    """Test the share functionality with detailed error reporting"""
    print("Testing share splitting and recombination...")
    
    # Create a secure storage instance
    secure_storage = SecureStorage()
    
    # Create a test database
    db = VectorDatabase(dimensions=5, size=0, threshold=1e-6, use_indexing=False)
    for i in range(10):
        vector = np.random.rand(5)
        db.add_vector(vector, {"index": i})
    
    # Create temp directory for test files
    with tempfile.TemporaryDirectory() as tempdir:
        output_dir = Path(tempdir)
        print(f"Using temporary directory: {output_dir}")
        
        # Test file paths
        db_file = output_dir / "share_test_db.json"
        
        # 1. Save with shares
        print("\nStep 1: Saving database with shares...")
        try:
            result = secure_storage.secure_save_vector_db(
                vector_db=db,
                filename=str(db_file),
                split_shares=3,
                threshold_shares=2,
                encryption_password="test-password",
                sign_data=True
            )
            print(f"Save result keys: {', '.join(result.keys())}")
            
            # Verify files were created
            recovery_file = db_file.with_suffix(".json.recovery_info")
            print(f"Recovery file exists: {recovery_file.exists()}")
            
            # List expected share files
            share_files = []
            for i in range(1, 4):
                share_file = db_file.with_suffix(f".json.share{i}")
                share_files.append(share_file)
                print(f"Share file {i} exists: {share_file.exists()}")
                
            # 2. Inspect the recovery file
            print("\nStep 2: Inspecting recovery file...")
            recovery_data = inspect_recovery_file(recovery_file)
            
            # 3. Inspect share files
            print("\nStep 3: Inspecting share files...")
            share_data_list = []
            for share_file in share_files:
                share_data = inspect_share_file(share_file)
                if share_data:
                    share_data_list.append(share_data)
            
            # 4. Try to combine shares directly
            print("\nStep 4: Testing direct share combination...")
            try:
                combined_data = secure_storage._combine_shares(share_data_list)
                print(f"Combined data length: {len(combined_data)}")
                
                # Try to parse the combined data
                try:
                    db_json = combined_data.decode('utf-8')
                    vector_db = VectorDatabase.from_json(db_json)
                    print(f"Successfully loaded vector database directly: {vector_db.dimensions}x{vector_db.size}")
                except UnicodeDecodeError:
                    print("UTF-8 decoding failed, trying different approaches...")
                    try:
                        # Try to decode with latin-1
                        db_json = combined_data.decode('latin-1')
                        vector_db = VectorDatabase.from_json(db_json)
                        print(f"Successfully loaded using latin-1 encoding: {vector_db.dimensions}x{vector_db.size}")
                    except Exception as e2:
                        print(f"Latin-1 decoding failed: {str(e2)}")
                        
                        # Try to write to a temp file and load
                        temp_file = output_dir / "temp_combined.json"
                        with open(temp_file, 'wb') as f:
                            f.write(combined_data)
                        
                        # Display hex dump of first 50 bytes
                        print("Hex dump of first 50 bytes:")
                        hex_dump = ' '.join([f"{b:02x}" for b in combined_data[:50]])
                        print(hex_dump)
                
                # 5. Try to decrypt PQC protection if present
                print("\nStep 5: Testing PQC decryption...")
                try:
                    # Check if the data might be PQC protected
                    if combined_data.startswith(b'{"') or combined_data.startswith(b'{\n'):
                        print("Data appears to be in JSON format, checking for PQC protection...")
                        try:
                            json_data = json.loads(combined_data.decode('utf-8'))
                            if isinstance(json_data, dict) and 'algorithm' in json_data:
                                print(f"Found encryption: {json_data['algorithm']}")
                                if 'SIMULATED-PQC' in json_data['algorithm']:
                                    decrypted = secure_storage._simulate_pqc_decrypt(json_data)
                                    print(f"Successfully decrypted PQC protection, result length: {len(decrypted)}")
                        except Exception as e:
                            print(f"Error parsing/decrypting JSON: {str(e)}")
                except Exception as e:
                    print(f"PQC decryption test failed: {str(e)}")
            except Exception as e:
                print(f"Error combining shares: {str(e)}")
            
            # 6. Finally try the proper API for loading
            print("\nStep 6: Testing secure_load_vector_db with all shares...")
            try:
                loaded_db, info = secure_storage.secure_load_vector_db(
                    share_files=[str(sf) for sf in share_files],
                    encryption_password="test-password"
                )
                print(f"Successfully loaded database: {loaded_db.dimensions}x{loaded_db.size}")
                print(f"Security info keys: {', '.join(info.keys())}")
            except Exception as e:
                print(f"Error loading with all shares: {str(e)}")
            
            # 7. Try with recovery info file
            print("\nStep 7: Testing secure_load_vector_db with recovery info...")
            try:
                loaded_db, info = secure_storage.secure_load_vector_db(
                    recovery_info_file=str(recovery_file),
                    encryption_password="test-password"
                )
                print(f"Successfully loaded database: {loaded_db.dimensions}x{loaded_db.size}")
                print(f"Security info keys: {', '.join(info.keys())}")
            except Exception as e:
                print(f"Error loading with recovery info: {str(e)}")
                
        except Exception as e:
            print(f"Error in share testing: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_shares() 