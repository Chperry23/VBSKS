"""
Test script for dynamic map reconfiguration system.

This script tests the functionality of the MapManager and ReconfigurationController
components of the VBSKS system.
"""

import os
import time
import shutil
import logging
import numpy as np
from vector_db import VectorDatabase
from key_manager import KeyManager
from secure_storage import SecureStorage
from map_manager import MapManager
from reconfiguration_controller import ReconfigurationController

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_reconfiguration')

# Test directory setup
TEST_DIR = "reconfiguration_test"
if os.path.exists(TEST_DIR):
    shutil.rmtree(TEST_DIR)
os.makedirs(TEST_DIR, exist_ok=True)

def create_test_components():
    """Create test components for the reconfiguration system."""
    logger.info("Creating test components...")
    
    # Create a vector database
    dimensions = 20
    size = 1000
    db = VectorDatabase(dimensions=dimensions, size=size, threshold=1e-6, use_indexing=True)
    
    # Initialize with random vectors
    for i in range(size):
        vector = np.random.uniform(0, 1, dimensions)
        vector = vector / np.linalg.norm(vector)  # Normalize
        db.store_vector(i, vector, {"type": "random", "created_at": time.time()})
    
    # Create a key manager
    key_manager = KeyManager()
    
    # Create a secure storage
    secure_storage = SecureStorage()
    
    # Create a map manager
    map_manager = MapManager(
        master_password="test_password",
        vector_db_size=size,
        key_length=10,
        reconfiguration_interval=3600  # 1 hour
    )
    
    # Create a reconfiguration controller
    audit_log_file = os.path.join(TEST_DIR, "audit.log")
    controller = ReconfigurationController(
        vector_db=db,
        key_manager=key_manager,
        map_manager=map_manager,
        secure_storage=secure_storage,
        audit_log_file=audit_log_file
    )
    
    return db, key_manager, secure_storage, map_manager, controller

def test_map_manager():
    """Test the MapManager component."""
    logger.info("Testing MapManager...")
    
    # Create a map manager
    map_manager = MapManager(
        master_password="test_password",
        vector_db_size=1000,
        key_length=10
    )
    
    # Generate positions
    positions = map_manager.generate_new_positions()
    assert len(positions) == 10, f"Expected 10 positions, got {len(positions)}"
    assert len(set(positions)) == 10, "Positions should be unique"
    logger.info(f"Generated positions: {positions}")
    
    # Test saving and loading map
    map_file = os.path.join(TEST_DIR, "test_map.vbsks_map")
    result = map_manager.save_map_file(positions, map_file)
    assert os.path.exists(map_file), f"Map file {map_file} not created"
    logger.info(f"Map file created: {map_file}")
    
    # Verify checksum
    assert result['checksum'] is not None, "Checksum should be present"
    
    # Load map
    loaded_positions = map_manager.load_map_file(map_file)
    assert loaded_positions == positions, "Loaded positions don't match original"
    logger.info("Map file loaded successfully")
    
    # Test should_reconfigure
    assert not map_manager.should_reconfigure(), "Should not need reconfiguration yet"
    
    # Force reconfiguration by setting interval to a small value
    map_manager.reconfiguration_interval = 0.1  # 0.1 seconds
    time.sleep(0.2)  # Wait a bit
    assert map_manager.should_reconfigure(), "Should need reconfiguration now"
    logger.info("Reconfiguration timing check passed")
    
    return map_manager

def test_basic_reconfiguration():
    """Test basic reconfiguration functionality."""
    logger.info("Testing basic reconfiguration...")
    
    # Create test components
    db, key_manager, secure_storage, map_manager, controller = create_test_components()
    
    # Create "key vectors" (just random vectors for testing)
    key_vectors = np.random.uniform(0, 1, (10, db.dimensions))
    for i in range(key_vectors.shape[0]):
        key_vectors[i] = key_vectors[i] / np.linalg.norm(key_vectors[i])  # Normalize
    
    # Generate initial positions
    initial_positions = map_manager.generate_new_positions()
    
    # Store key vectors at initial positions
    for i, pos in enumerate(initial_positions):
        db.store_vector(pos, key_vectors[i], {"key_vector_index": i})
    
    # Test reconfiguration
    new_positions, result = controller.reconfigure(
        positions=initial_positions,
        key_vectors=key_vectors,
        requester_id="test_script"
    )
    
    assert len(new_positions) == len(initial_positions), "New positions length mismatch"
    assert set(new_positions) != set(initial_positions), "Positions didn't change"
    assert result['status'] == 'completed', f"Reconfiguration failed: {result.get('error', 'Unknown error')}"
    
    # Verify key vectors at new positions
    for i, pos in enumerate(new_positions):
        vector, metadata = db.retrieve_vector(pos)
        assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
        assert metadata.get('key_vector_index') == i, "Metadata mismatch"
    
    logger.info("Basic reconfiguration test passed")
    
    # Check that old positions now contain noise
    for pos in initial_positions:
        vector, metadata = db.retrieve_vector(pos)
        assert metadata.get('is_noise') == True, f"Position {pos} should contain noise"
    
    logger.info("Old positions contain noise as expected")
    
    return new_positions, key_vectors, controller

def test_map_load_reconfiguration():
    """Test loading a map and reconfiguring based on it."""
    logger.info("Testing map load and reconfiguration...")
    
    # Get components from basic reconfiguration test
    new_positions, key_vectors, controller = test_basic_reconfiguration()
    
    # Save the map to a file
    map_file = os.path.join(TEST_DIR, "test_map_load.vbsks_map")
    controller.map_manager.save_map_file(new_positions, map_file)
    
    # Create a fresh set of components
    db, key_manager, secure_storage, map_manager, controller = create_test_components()
    
    # Load the map and reconfigure
    loaded_positions, result = controller.load_map_and_reconfigure(
        map_filename=map_file,
        key_vectors=key_vectors,
        requester_id="test_script"
    )
    
    assert len(loaded_positions) == len(new_positions), "Loaded positions length mismatch"
    assert loaded_positions == new_positions, "Loaded positions don't match saved positions"
    assert result['status'] == 'completed', f"Map load reconfiguration failed: {result.get('error', 'Unknown error')}"
    
    # Verify key vectors at loaded positions
    for i, pos in enumerate(loaded_positions):
        vector, metadata = db.retrieve_vector(pos)
        assert np.allclose(vector, key_vectors[i]), f"Vector at position {pos} doesn't match"
    
    logger.info("Map load reconfiguration test passed")

def test_reconfiguration_with_rollback():
    """Test reconfiguration with rollback on failure."""
    logger.info("Testing reconfiguration with rollback...")
    
    # Create test components
    db, key_manager, secure_storage, map_manager, controller = create_test_components()
    
    # Create "key vectors"
    key_vectors = np.random.uniform(0, 1, (10, db.dimensions))
    for i in range(key_vectors.shape[0]):
        key_vectors[i] = key_vectors[i] / np.linalg.norm(key_vectors[i])  # Normalize
    
    # Generate initial positions
    initial_positions = map_manager.generate_new_positions()
    
    # Store key vectors at initial positions
    for i, pos in enumerate(initial_positions):
        db.store_vector(pos, key_vectors[i], {"key_vector_index": i})
    
    # Backup key vectors and positions
    backup_key_vectors = key_vectors.copy()
    backup_positions = initial_positions.copy()
    
    # Monkey patch the store_vector method to fail after a few vectors
    original_store_vector = db.store_vector
    
    def failing_store_vector(index, vector, metadata):
        if metadata.get('key_vector_index', -1) >= 5:
            raise ValueError("Simulated failure during reconfiguration")
        return original_store_vector(index, vector, metadata)
    
    # Apply the monkey patch
    db.store_vector = failing_store_vector
    
    # Try to reconfigure - this should fail
    try:
        controller.reconfigure(
            positions=initial_positions,
            key_vectors=key_vectors,
            requester_id="test_script"
        )
        assert False, "Reconfiguration should have failed"
    except ValueError as e:
        logger.info(f"Reconfiguration failed as expected: {str(e)}")
    
    # Restore the original method
    db.store_vector = original_store_vector
    
    # Verify that the original vectors are still in place (rollback worked)
    for i, pos in enumerate(initial_positions):
        vector, metadata = db.retrieve_vector(pos)
        
        # Vectors might be slightly different due to numerical precision in rollback
        assert np.allclose(vector, backup_key_vectors[i]), f"Vector at position {pos} doesn't match after rollback"
        assert metadata.get('key_vector_index') == i, "Metadata mismatch after rollback"
    
    logger.info("Reconfiguration rollback test passed")

def main():
    """Run all tests."""
    try:
        logger.info("Starting reconfiguration system tests...")
        
        test_map_manager()
        test_basic_reconfiguration()
        test_map_load_reconfiguration()
        test_reconfiguration_with_rollback()
        
        logger.info("All reconfiguration system tests passed!")
        return 0
    except Exception as e:
        logger.error(f"Tests failed: {str(e)}", exc_info=True)
        return 1
    finally:
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)
            logger.info(f"Removed test directory: {TEST_DIR}")

if __name__ == "__main__":
    exit(main()) 