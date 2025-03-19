#!/usr/bin/env python3
"""
VBSKS Dynamic Reconfiguration Example

This script demonstrates how to use the dynamic map reconfiguration system
with the Vector-Based Secure Key Storage system.
"""

import os
import time
import numpy as np
import json
from pathlib import Path

from vector_db import VectorDatabase
from key_manager import QuantumResistantKeyManager
from map_manager import MapManager
from reconfiguration_controller import ReconfigurationController
from secure_storage import SecureStorage

def create_test_components():
    """Create the necessary components for testing reconfiguration"""
    print("\n=== Creating Test Components ===")
    
    # Create vector database
    dimensions = 20
    size = 1000
    print(f"Creating vector database ({dimensions} dimensions, {size} size)...")
    db = VectorDatabase(dimensions=dimensions, size=size, threshold=1e-6, use_indexing=True)
    
    # Initialize with some random vectors
    for i in range(100):
        vector = np.random.rand(dimensions)
        vector = vector / np.linalg.norm(vector)  # Normalize
        db.store_vector(i, vector, {"type": "random", "created_at": time.time()})
    
    # Create key manager with reconfiguration enabled
    print("Creating quantum-resistant key manager with reconfiguration enabled...")
    key_manager = QuantumResistantKeyManager(
        vector_db=db,
        key_length=10,
        enable_reconfiguration=True,
        reconfiguration_interval=60,  # 1 minute for testing
        reconfiguration_password="test_reconfiguration_password"
    )
    
    # Create secure storage
    secure_storage = SecureStorage()
    
    # Create reconfiguration controller
    print("Creating reconfiguration controller...")
    controller = ReconfigurationController(
        vector_db=db,
        key_manager=key_manager,
        map_manager=key_manager.map_manager,
        secure_storage=secure_storage,
        audit_log_file="reconfiguration_audit.log"
    )
    
    print("Components created successfully!")
    return db, key_manager, secure_storage, controller

def generate_and_store_key(key_manager):
    """Generate and store a key"""
    print("\n=== Generating and Storing Key ===")
    
    # Generate key with deterministic positions
    secret_seed = "test_seed_for_key_generation"
    print(f"Generating key with seed: {secret_seed}")
    key_vectors, positions = key_manager.generate_key(secret_seed)
    
    print(f"Generated key with {len(positions)} vector positions:")
    print(f"Positions: {positions}")
    
    # Save key data
    key_file = "test_key.json"
    print(f"Saving key data to {key_file}...")
    
    if isinstance(key_manager, QuantumResistantKeyManager):
        # Use secure method with map file
        result = key_manager.save_key_data_secure(
            filename=key_file,
            key_vectors=key_vectors,
            positions=positions,
            metadata={"description": "Test key for reconfiguration", "created_at": time.time()},
            encryption_password="test_password",
            save_map=True
        )
        print(f"Key data saved securely with {len(result.get('files', {}))} files")
        if 'map_file' in result:
            print(f"Map file saved to: {result['map_file']}")
    else:
        # Use standard method
        key_manager.save_key_data(
            filename=key_file,
            key_vectors=key_vectors,
            positions=positions,
            metadata={"description": "Test key for reconfiguration", "created_at": time.time()}
        )
        print(f"Key data saved to {key_file}")
        
        # Save map separately
        map_file = f"{key_file}.map"
        key_manager.save_map(positions, map_file)
        print(f"Map file saved to {map_file}")
    
    return key_vectors, positions, key_file

def test_reconfiguration(controller, key_manager, key_vectors, positions):
    """Test the reconfiguration process"""
    print("\n=== Testing Reconfiguration ===")
    
    # 1. Check if reconfiguration is needed
    print("Checking if reconfiguration is needed...")
    reconfig_needed = controller.check_reconfiguration_needed(positions)
    print(f"Reconfiguration needed: {reconfig_needed}")
    
    # If not needed, we'll force it for testing
    if not reconfig_needed:
        print("Forcing reconfiguration for testing purposes...")
    
    # 2. Perform reconfiguration
    print("Performing reconfiguration...")
    try:
        new_positions, result = controller.reconfigure(
            positions=positions,
            key_vectors=key_vectors,
            requester_id="example_script"
        )
        
        print(f"Reconfiguration status: {result.get('status', 'unknown')}")
        
        if result.get('status') == 'completed':
            print(f"New positions: {new_positions}")
            
            # 3. Verify the key vectors are at the new positions
            print("Verifying key vectors at new positions...")
            all_match = True
            for i, pos in enumerate(new_positions):
                vector, metadata = key_manager.vector_db.retrieve_vector(pos)
                if not np.allclose(vector, key_vectors[i], atol=1e-6):
                    print(f"Vector mismatch at position {pos}!")
                    all_match = False
            
            if all_match:
                print("All vectors successfully moved to new positions!")
            
            # 4. Verify old positions now contain noise
            print("Verifying old positions now contain noise...")
            all_noise = True
            for pos in positions:
                vector, metadata = key_manager.vector_db.retrieve_vector(pos)
                if not metadata.get('is_noise', False):
                    print(f"Position {pos} does not contain noise metadata!")
                    all_noise = False
            
            if all_noise:
                print("All old positions successfully replaced with noise!")
            
            # Save the new map
            map_file = "new_positions.map"
            key_manager.save_map(new_positions, map_file)
            print(f"New map saved to {map_file}")
            
            return new_positions
        else:
            print(f"Reconfiguration failed: {result.get('error', 'unknown error')}")
            return None
    except Exception as e:
        print(f"Error during reconfiguration: {str(e)}")
        return None

def test_map_load_reconfiguration(controller, key_manager, key_vectors, original_positions):
    """Test loading a map and reconfiguring based on it"""
    print("\n=== Testing Map Load and Reconfiguration ===")
    
    # Create more random positions
    map_file = "manual_positions.map"
    
    # Generate completely new positions
    print("Generating new positions manually...")
    manual_positions = []
    while len(manual_positions) < len(original_positions):
        pos = np.random.randint(100, key_manager.vector_db.size)
        if pos not in manual_positions:
            manual_positions.append(pos)
    
    print(f"Manual positions: {manual_positions}")
    
    # Save to map file
    print(f"Saving manual positions to {map_file}...")
    key_manager.save_map(manual_positions, map_file)
    
    # Load map and reconfigure
    print("Loading map and reconfiguring...")
    try:
        new_positions, result = controller.load_map_and_reconfigure(
            map_filename=map_file,
            key_vectors=key_vectors,
            current_positions=original_positions,
            requester_id="example_script"
        )
        
        print(f"Reconfiguration status: {result.get('status', 'unknown')}")
        
        if result.get('status') == 'completed':
            print(f"New positions: {new_positions}")
            
            # Verify the key vectors are at the new positions
            print("Verifying key vectors at new positions...")
            all_match = True
            for i, pos in enumerate(new_positions):
                vector, metadata = key_manager.vector_db.retrieve_vector(pos)
                if not np.allclose(vector, key_vectors[i], atol=1e-6):
                    print(f"Vector mismatch at position {pos}!")
                    all_match = False
            
            if all_match:
                print("All vectors successfully moved to new positions!")
            
            # Verify manual positions
            equal_positions = sorted(new_positions) == sorted(manual_positions)
            print(f"New positions match manual positions: {equal_positions}")
            
            return new_positions
        else:
            print(f"Map-based reconfiguration failed: {result.get('error', 'unknown error')}")
            return None
    except Exception as e:
        print(f"Error during map-based reconfiguration: {str(e)}")
        return None

def test_automated_reconfiguration(controller, key_manager, key_vectors, positions):
    """Test automated reconfiguration based on time interval"""
    print("\n=== Testing Automated Reconfiguration ===")
    
    # Adjust reconfiguration interval to a small value
    if key_manager.map_manager:
        orig_interval = key_manager.map_manager.reconfiguration_interval
        key_manager.map_manager.reconfiguration_interval = 2  # 2 seconds
        
        print(f"Setting reconfiguration interval to {key_manager.map_manager.reconfiguration_interval} seconds")
        print("Waiting for interval to pass...")
        
        # Wait for the interval to pass
        time.sleep(3)
        
        # Check if reconfiguration is needed
        print("Checking if reconfiguration is needed...")
        reconfig_needed = controller.check_reconfiguration_needed(positions)
        print(f"Reconfiguration needed: {reconfig_needed}")
        
        if reconfig_needed:
            print("Performing automated reconfiguration...")
            try:
                new_positions, result = controller.reconfigure(
                    positions=positions,
                    key_vectors=key_vectors,
                    requester_id="example_script_automated"
                )
                
                print(f"Automated reconfiguration status: {result.get('status', 'unknown')}")
                
                if result.get('status') == 'completed':
                    print(f"New positions: {new_positions}")
                    return new_positions
                else:
                    print(f"Automated reconfiguration failed: {result.get('error', 'unknown error')}")
                    return None
            except Exception as e:
                print(f"Error during automated reconfiguration: {str(e)}")
                return None
        else:
            print("Automated reconfiguration was not triggered as expected")
            return None
    else:
        print("Map manager not available, skipping automated reconfiguration test")
        return None

def cleanup():
    """Clean up test files"""
    print("\n=== Cleaning Up ===")
    
    files_to_remove = [
        "test_key.json",
        "test_key.json.map",
        "new_positions.map",
        "manual_positions.map",
        "reconfiguration_audit.log"
    ]
    
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed {file}")

def main():
    """Main function to run all examples"""
    print("Vector-Based Secure Key Storage (VBSKS) - Dynamic Reconfiguration Example")
    print("======================================================================")
    
    try:
        # Create components
        db, key_manager, secure_storage, controller = create_test_components()
        
        # Generate and store a key
        key_vectors, original_positions, key_file = generate_and_store_key(key_manager)
        
        # Test basic reconfiguration
        new_positions = test_reconfiguration(controller, key_manager, key_vectors, original_positions)
        
        # Test map-based reconfiguration
        if new_positions:
            final_positions = test_map_load_reconfiguration(
                controller, key_manager, key_vectors, new_positions
            )
        
            # Test automated reconfiguration
            if final_positions:
                test_automated_reconfiguration(controller, key_manager, key_vectors, final_positions)
        
        print("\nAll examples completed!")
        return 0
    except Exception as e:
        print(f"Error in example: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        cleanup()

if __name__ == "__main__":
    exit(main()) 