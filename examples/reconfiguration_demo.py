#!/usr/bin/env python3
"""
Dynamic Reconfiguration Demo

This example demonstrates how VBSKS dynamically reconfigures keys for enhanced security.
"""

import os
import sys
import base64
import getpass
import time
import json

# Add parent directory to path for imports when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import VBSKS modules
from vbsks_easy import VBSKSEasy
from key_manager import QuantumResistantKeyManager
from map_manager import MapManager
from reconfiguration_controller import ReconfigurationController

def main():
    """Main function demonstrating key reconfiguration"""
    print("VBSKS Dynamic Reconfiguration Demo")
    print("==================================\n")
    
    # Initialize VBSKS with a custom folder and short reconfiguration interval
    db_folder = os.path.join(os.path.dirname(__file__), "reconfig_example_data")
    
    # Use a very short reconfiguration interval for demonstration
    # In production, this would typically be set to 24 hours or more
    reconfig_interval = 10  # 10 seconds for demo purposes
    
    vbsks = VBSKSEasy(
        db_folder=db_folder,
        auto_reconfigure=True,
        reconfiguration_interval=reconfig_interval,
        dimensions=100,
        db_size=5000,
        key_length=8
    )
    
    print(f"Initialized VBSKS in folder: {db_folder}")
    print(f"Reconfiguration interval: {reconfig_interval} seconds\n")
    
    # Get master password for operations
    master_password = getpass.getpass("Enter master password: ")
    
    # Part 1: Store a key and save its position
    print("\n1. Storing a new key...")
    key_id = "dynamic_key"
    secret_data = "This is a secret that will be dynamically reconfigured"
    
    result = vbsks.store_key(
        key_id=key_id,
        master_password=master_password,
        data=secret_data,
        metadata={"description": "Dynamic key demonstration"}
    )
    
    if result['status'] != 'success':
        print(f"Error storing key: {result.get('error', 'Unknown error')}")
        return
    
    print(f"Key '{key_id}' stored successfully")
    
    # Get the initial positions from the key map
    initial_positions = vbsks.key_map[key_id]['positions']
    print(f"\nInitial positions: {initial_positions}")
    
    # Part 2: Wait for reconfiguration interval
    wait_time = reconfig_interval + 2  # Add a couple seconds buffer
    print(f"\n2. Waiting {wait_time} seconds for reconfiguration...")
    
    # Save the initial map file for comparison
    map_file = os.path.join(db_folder, "initial_map.json")
    with open(map_file, 'w') as f:
        json.dump({"key_id": key_id, "positions": initial_positions}, f, indent=2)
    
    print(f"Saved initial positions to: {map_file}")
    
    # Wait for reconfiguration interval
    time.sleep(wait_time)
    
    # Part 3: Retrieve the key and check if positions changed
    print("\n3. Retrieving key after waiting...")
    result = vbsks.retrieve_key(
        key_id=key_id,
        master_password=master_password
    )
    
    if result['status'] != 'success':
        print(f"Error retrieving key: {result.get('error', 'Unknown error')}")
        return
    
    # Check if the key was reconfigured
    was_reconfigured = result.get('reconfigured', False)
    new_positions = vbsks.key_map[key_id]['positions']
    
    print(f"Key '{key_id}' retrieved successfully")
    print(f"Was key reconfigured: {was_reconfigured}")
    
    # Compare positions
    positions_changed = new_positions != initial_positions
    print(f"Positions changed: {positions_changed}")
    
    # Save the new positions for comparison
    new_map_file = os.path.join(db_folder, "new_map.json")
    with open(new_map_file, 'w') as f:
        json.dump({"key_id": key_id, "positions": new_positions}, f, indent=2)
    
    print(f"Saved new positions to: {new_map_file}")
    
    if positions_changed:
        print("\nInitial positions:")
        print(initial_positions)
        print("\nNew positions after reconfiguration:")
        print(new_positions)
    
    # Part 4: Manual reconfiguration
    print("\n4. Demonstrating manual reconfiguration...")
    
    # Access the reconfiguration controller directly
    controller = vbsks.controller
    
    # Get current key vectors from their positions
    key_vectors = []
    for pos in new_positions:
        vector = vbsks.vector_db.get_vector(pos)
        key_vectors.append(vector)
    
    # Manually trigger reconfiguration
    manual_positions, result = controller.reconfigure(
        positions=new_positions,
        key_vectors=key_vectors,
        requester_id="manual_demo"
    )
    
    print(f"Manual reconfiguration completed: {result}")
    print(f"Manually reconfigured positions: {manual_positions}")
    
    # Save the manual reconfiguration map
    manual_map_file = os.path.join(db_folder, "manual_map.json")
    with open(manual_map_file, 'w') as f:
        json.dump({"key_id": key_id, "positions": manual_positions}, f, indent=2)
    
    print(f"Saved manual reconfiguration positions to: {manual_map_file}")
    
    # Update key map with new positions
    vbsks.key_map[key_id]['positions'] = manual_positions
    vbsks._save_key_map()
    
    # Save database
    vbsks.vector_db.save(str(os.path.join(db_folder, "vbsks_db.json")))
    
    # Part 5: Verify the reconfigured key can still be retrieved
    print("\n5. Verifying key can be retrieved after manual reconfiguration...")
    
    result = vbsks.retrieve_key(
        key_id=key_id,
        master_password=master_password
    )
    
    if result['status'] == 'success':
        print(f"Key successfully retrieved after manual reconfiguration")
        
        # Decode the key
        crypto_key = result['crypto_key']
        key_bytes = base64.b64decode(crypto_key)
        try:
            key_text = key_bytes.decode('utf-8')
            print(f"\nRetrieved key value: {key_text}")
            
            # Verify the data matches what we originally stored
            if key_text == secret_data:
                print("\nSUCCESS: The retrieved key matches the original secret data!")
            else:
                print("\nWARNING: The retrieved key does not match the original data.")
        except:
            print(f"\nRetrieved key (base64): {crypto_key}")
    else:
        print(f"Error retrieving key after reconfiguration: {result.get('error', 'Unknown error')}")
    
    print("\nReconfiguration demonstration completed.")

if __name__ == "__main__":
    main() 