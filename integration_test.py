#!/usr/bin/env python3
"""
VBSKS Dynamic Reconfiguration Integration Test

This script performs a comprehensive integration test of the dynamic map 
reconfiguration system with the full VBSKS system.
"""

import os
import sys
import time
import shutil
import logging
import numpy as np
import json
from pathlib import Path
import hashlib
import base64
from datetime import datetime

from vector_db import VectorDatabase
from key_manager import KeyManager, QuantumResistantKeyManager
from map_manager import MapManager
from reconfiguration_controller import ReconfigurationController
from secure_storage import SecureStorage

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('integration_test')

# Test directory
TEST_DIR = "integration_test_data"

def setup_test_environment():
    """Set up the test environment"""
    logger.info("Setting up test environment")
    
    # Create test directory
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)
    
    # Create components
    db = VectorDatabase(dimensions=32, size=2000, threshold=1e-6, use_indexing=True)
    
    # Add some random vectors
    for i in range(200):
        vector = np.random.rand(32)
        vector = vector / np.linalg.norm(vector)  # Normalize
        db.store_vector(i, vector, {"type": "test", "index": i})
    
    # Create key manager
    key_manager = QuantumResistantKeyManager(
        vector_db=db,
        key_length=8,
        threshold=1e-6,
        quantum_algorithm="Simulate",
        enable_reconfiguration=True,
        reconfiguration_interval=300,  # 5 minutes
        reconfiguration_password="integration_test_password"
    )
    
    # Create secure storage
    secure_storage = SecureStorage(quantum_algorithm="Simulate")
    
    # Create reconfiguration controller
    controller = ReconfigurationController(
        vector_db=db,
        key_manager=key_manager,
        map_manager=key_manager.map_manager,
        secure_storage=secure_storage,
        audit_log_file=os.path.join(TEST_DIR, "reconfiguration_audit.log")
    )
    
    return db, key_manager, secure_storage, controller

def test_key_generation_and_storage(key_manager, secure_storage):
    """Test key generation and storage"""
    logger.info("Testing key generation and storage")
    
    # Generate a key
    secret_seed = "integration_test_seed"
    key_vectors, positions = key_manager.generate_key(secret_seed)
    
    logger.info(f"Generated key with {len(positions)} positions: {positions}")
    
    # Verify key
    is_valid = key_manager.verify_key(positions, key_vectors)
    assert is_valid, "Key verification failed"
    logger.info("Key verification successful")
    
    # Save key data
    key_file = os.path.join(TEST_DIR, "test_key.json")
    if isinstance(key_manager, QuantumResistantKeyManager):
        result = key_manager.save_key_data_secure(
            filename=key_file,
            key_vectors=key_vectors,
            positions=positions,
            metadata={"description": "Integration test key", "timestamp": datetime.now().isoformat()},
            encryption_password="test_password",
            save_map=True
        )
        logger.info(f"Key data saved securely with {len(result.get('files', {}))} files")
        
        # Verify map file was created
        map_file = f"{key_file}.map"
        assert os.path.exists(map_file), f"Map file {map_file} not created"
        logger.info(f"Map file created: {map_file}")
    else:
        key_manager.save_key_data(
            filename=key_file,
            key_vectors=key_vectors,
            positions=positions
        )
        logger.info(f"Key data saved to {key_file}")
    
    # Load key data
    if isinstance(key_manager, QuantumResistantKeyManager):
        loaded_data = QuantumResistantKeyManager.load_key_data_secure(
            source=key_file,
            encryption_password="test_password"
        )
    else:
        loaded_data = KeyManager.load_key_data(key_file)
    
    # Verify loaded data
    assert np.allclose(loaded_data['key_vectors'], key_vectors), "Loaded key vectors don't match"
    assert loaded_data['positions'] == positions, "Loaded positions don't match"
    logger.info("Key data loading successful")
    
    # Save to database file
    db_file = os.path.join(TEST_DIR, "test_db.json")
    key_manager.vector_db.save(db_file)
    logger.info(f"Vector database saved to {db_file}")
    
    # Secure save
    secure_db_file = os.path.join(TEST_DIR, "secure_db.json")
    secure_result = secure_storage.secure_save_vector_db(
        vector_db=key_manager.vector_db,
        filename=secure_db_file,
        encryption_password="test_password",
        add_statistical_noise=True,
        sign_data=True
    )
    logger.info(f"Vector database saved securely to {secure_db_file}")
    
    return key_vectors, positions, key_file, db_file, secure_db_file

def test_basic_reconfiguration(controller, key_manager, key_vectors, positions):
    """Test basic reconfiguration"""
    logger.info("Testing basic reconfiguration")
    
    # Save original positions
    original_positions = positions.copy()
    
    # Perform reconfiguration
    new_positions, result = controller.reconfigure(
        positions=positions,
        key_vectors=key_vectors,
        requester_id="integration_test"
    )
    
    assert result['status'] == 'completed', f"Reconfiguration failed: {result.get('error', 'Unknown error')}"
    logger.info(f"Reconfiguration completed with new positions: {new_positions}")
    
    # Verify new positions are different
    assert set(new_positions) != set(original_positions), "New positions should be different"
    
    # Verify key vectors are at new positions
    for i, pos in enumerate(new_positions):
        vector, metadata = key_manager.vector_db.retrieve_vector(pos)
        assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
    logger.info("Key vectors successfully moved to new positions")
    
    # Verify old positions now contain noise
    for pos in original_positions:
        vector, metadata = key_manager.vector_db.retrieve_vector(pos)
        assert metadata.get('is_noise', False), f"Position {pos} should contain noise"
    logger.info("Old positions successfully replaced with noise")
    
    # Save map
    map_file = os.path.join(TEST_DIR, "reconfigured_map.json")
    key_manager.save_map(new_positions, map_file)
    logger.info(f"New map saved to {map_file}")
    
    # Save database with updated vectors
    db_file = os.path.join(TEST_DIR, "test_db_reconfigured.json")
    key_manager.vector_db.save(db_file)
    logger.info(f"Updated vector database saved to {db_file}")
    
    return new_positions, map_file, db_file

def test_recovery_after_restart(key_manager, controller, key_vectors, positions, map_file, db_file):
    """Test recovery after restart"""
    logger.info("Testing recovery after restart (simulating restart)")
    
    # Create new database from saved file
    new_db = VectorDatabase.load(db_file)
    logger.info(f"Loaded database from {db_file}")
    
    # Create new key manager
    new_key_manager = QuantumResistantKeyManager(
        vector_db=new_db,
        key_length=key_manager.key_length,
        threshold=key_manager.threshold,
        quantum_algorithm="Simulate",
        enable_reconfiguration=True,
        reconfiguration_interval=300,
        reconfiguration_password="integration_test_password"
    )
    
    # Create new secure storage
    new_secure_storage = SecureStorage(quantum_algorithm="Simulate")
    
    # Create new controller
    new_controller = ReconfigurationController(
        vector_db=new_db,
        key_manager=new_key_manager,
        map_manager=new_key_manager.map_manager,
        secure_storage=new_secure_storage
    )
    
    # Load the map
    loaded_positions = new_key_manager.load_map(map_file)
    assert loaded_positions == positions, f"Loaded positions don't match: {loaded_positions} vs {positions}"
    logger.info(f"Loaded map from {map_file}")
    
    # Verify key vectors
    for i, pos in enumerate(loaded_positions):
        vector, metadata = new_db.retrieve_vector(pos)
        assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
    logger.info("Key vectors verified after restart")
    
    # Perform another reconfiguration
    final_positions, result = new_controller.reconfigure(
        positions=loaded_positions,
        key_vectors=key_vectors,
        requester_id="integration_test_restart"
    )
    
    assert result['status'] == 'completed', f"Reconfiguration after restart failed: {result.get('error', 'Unknown error')}"
    logger.info(f"Reconfiguration after restart completed with new positions: {final_positions}")
    
    # Save the updated database
    restart_db_file = os.path.join(TEST_DIR, "test_db_restart.json")
    new_db.save(restart_db_file)
    logger.info(f"Updated vector database saved to {restart_db_file}")
    
    return final_positions, restart_db_file

def test_map_load_reconfiguration(controller, key_manager, key_vectors, positions, db_file):
    """Test map load and reconfiguration"""
    logger.info("Testing map load and reconfiguration")
    
    # First, make sure we have the latest database
    db = VectorDatabase.load(db_file)
    key_manager.vector_db = db
    controller.vector_db = db
    
    # Create manual positions
    manual_positions = []
    while len(manual_positions) < len(positions):
        pos = np.random.randint(500, key_manager.vector_db.size)
        if pos not in manual_positions:
            manual_positions.append(pos)
    
    logger.info(f"Generated manual positions: {manual_positions}")
    
    # Save map
    map_file = os.path.join(TEST_DIR, "manual_map.json")
    key_manager.save_map(manual_positions, map_file)
    logger.info(f"Manual map saved to {map_file}")
    
    # Load map and reconfigure
    new_positions, result = controller.load_map_and_reconfigure(
        map_filename=map_file,
        key_vectors=key_vectors,
        current_positions=positions,
        requester_id="integration_test_map_load"
    )
    
    assert result['status'] == 'completed', f"Map load reconfiguration failed: {result.get('error', 'Unknown error')}"
    logger.info(f"Map load reconfiguration completed with new positions: {new_positions}")
    
    # Verify positions match manual positions
    assert sorted(new_positions) == sorted(manual_positions), "Loaded positions don't match manual positions"
    
    # Verify key vectors
    for i, pos in enumerate(new_positions):
        vector, metadata = key_manager.vector_db.retrieve_vector(pos)
        assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
    logger.info("Key vectors successfully moved to manual positions")
    
    # Save the database
    map_load_db_file = os.path.join(TEST_DIR, "test_db_map_load.json")
    key_manager.vector_db.save(map_load_db_file)
    logger.info(f"Updated vector database saved to {map_load_db_file}")
    
    return new_positions, map_load_db_file

def test_secure_reconfiguration(key_manager, key_vectors, positions):
    """Test secure reconfiguration with backup"""
    logger.info("Testing secure reconfiguration with backup")
    
    # Create backup file
    backup_file = os.path.join(TEST_DIR, "pre_reconfig_backup.json")
    
    # Perform secure reconfiguration
    if isinstance(key_manager, QuantumResistantKeyManager):
        new_positions, result = key_manager.reconfigure_key_secure(
            positions=positions,
            key_vectors=key_vectors,
            backup_file=backup_file,
            encryption_password="test_password"
        )
        
        assert result['status'] == 'completed', f"Secure reconfiguration failed: {result.get('error', 'Unknown error')}"
        logger.info(f"Secure reconfiguration completed with new positions: {new_positions}")
        
        # Verify backup was created
        assert os.path.exists(backup_file), f"Backup file {backup_file} not created"
        logger.info(f"Backup file created: {backup_file}")
        
        # Verify map file was created
        new_map_file = result.get('new_map_file')
        if new_map_file:
            assert os.path.exists(new_map_file), f"New map file {new_map_file} not created"
            logger.info(f"New map file created: {new_map_file}")
        
        # Verify key vectors
        for i, pos in enumerate(new_positions):
            vector, metadata = key_manager.vector_db.retrieve_vector(pos)
            assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
        logger.info("Key vectors successfully moved to new positions")
        
        return new_positions
    else:
        logger.info("Skipping secure reconfiguration (requires QuantumResistantKeyManager)")
        return positions

def cleanup():
    """Clean up test environment"""
    logger.info("Cleaning up test environment")
    
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
        logger.info(f"Removed test directory: {TEST_DIR}")

def run_integration_tests():
    """Run all integration tests"""
    logger.info("Starting VBSKS Dynamic Reconfiguration Integration Tests")
    
    try:
        # Set up test environment
        db, key_manager, secure_storage, controller = setup_test_environment()
        
        # Test key generation and storage
        key_vectors, positions, key_file, db_file, secure_db_file = test_key_generation_and_storage(
            key_manager, secure_storage
        )
        
        # Test basic reconfiguration
        new_positions, map_file, db_file = test_basic_reconfiguration(
            controller, key_manager, key_vectors, positions
        )
        
        # Test recovery after restart
        restart_positions, restart_db_file = test_recovery_after_restart(
            key_manager, controller, key_vectors, new_positions, map_file, db_file
        )
        
        # Test map load reconfiguration
        map_load_positions, map_load_db_file = test_map_load_reconfiguration(
            controller, key_manager, key_vectors, restart_positions, restart_db_file
        )
        
        # Test secure reconfiguration
        final_positions = test_secure_reconfiguration(
            key_manager, key_vectors, map_load_positions
        )
        
        logger.info("All integration tests passed!")
        return 0
    except Exception as e:
        logger.error(f"Integration test failed: {str(e)}", exc_info=True)
        return 1
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(run_integration_tests()) 