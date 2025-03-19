#!/usr/bin/env python3
"""
ReconfigurationController - Manages dynamic reconfiguration of key vectors

This module provides functionality for reconfiguring key vectors within the vector database,
providing an additional layer of security against long-term statistical analysis.
"""

import os
import time
import json
import logging
import hashlib
import numpy as np
from typing import List, Dict, Tuple, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ReconfigurationController')

class ReconfigurationController:
    """
    Manages the dynamic reconfiguration of key vectors within the vector database.
    
    This controller handles:
    1. Determining when reconfiguration is needed
    2. Generating new positions for key vectors
    3. Moving key vectors to new positions
    4. Updating position maps
    5. Creating audit logs of reconfiguration operations
    """
    
    def __init__(
        self,
        vector_db,
        key_manager,
        map_manager,
        secure_storage=None,
        reconfiguration_interval: int = 86400,  # Default: once per day
        backup_dir: str = None,
        audit_log_file: str = None
    ):
        """
        Initialize the ReconfigurationController.
        
        Args:
            vector_db: The vector database instance
            key_manager: The key manager instance
            map_manager: The map manager instance
            secure_storage: Optional secure storage instance
            reconfiguration_interval: Time between reconfigurations (seconds)
            backup_dir: Directory for storing backups
            audit_log_file: File for recording reconfiguration events
        """
        self.vector_db = vector_db
        self.key_manager = key_manager
        self.map_manager = map_manager
        self.secure_storage = secure_storage
        
        # Reconfiguration settings
        self.reconfiguration_interval = reconfiguration_interval
        self.last_reconfiguration_time = time.time()
        
        # Backup settings
        self.backup_dir = backup_dir
        if backup_dir and not os.path.exists(backup_dir):
            os.makedirs(backup_dir, exist_ok=True)
        
        # Audit logging
        self.audit_log_file = audit_log_file
        if audit_log_file and not os.path.isabs(audit_log_file):
            # If a relative path is provided, make it relative to the backup_dir
            if backup_dir:
                self.audit_log_file = os.path.join(backup_dir, audit_log_file)
    
    def check_reconfiguration_needed(
        self,
        positions: List[int],
        force: bool = False
    ) -> bool:
        """
        Check if reconfiguration is needed for the given positions.
        
        Args:
            positions: List of current vector positions
            force: Force reconfiguration regardless of timing
        
        Returns:
            True if reconfiguration is needed, False otherwise
        """
        if force:
            return True
        
        # Check reconfiguration timing
        current_time = time.time()
        elapsed_time = current_time - self.last_reconfiguration_time
        
        # Get position metadata to check last reconfiguration
        position_reconfig_times = []
        for pos in positions:
            metadata = self.vector_db.get_metadata(pos)
            if metadata and 'last_reconfigured' in metadata:
                position_reconfig_times.append(metadata['last_reconfigured'])
        
        # If we have timing info for any position
        if position_reconfig_times:
            # Use the oldest reconfiguration time
            oldest_reconfig = min(position_reconfig_times)
            position_elapsed = current_time - oldest_reconfig
            
            # Check if the position-specific elapsed time exceeds interval
            if position_elapsed >= self.reconfiguration_interval:
                logger.info(f"Reconfiguration needed: Position-specific time elapsed ({position_elapsed:.1f} seconds)")
                return True
        
        # Otherwise, use the controller's last reconfiguration time
        if elapsed_time >= self.reconfiguration_interval:
            logger.info(f"Reconfiguration needed: Controller time elapsed ({elapsed_time:.1f} seconds)")
            return True
        
        return False
    
    def reconfigure(
        self, 
        positions: List[int],
        key_vectors: List[np.ndarray],
        requester_id: str = "system"
    ) -> Tuple[List[int], str]:
        """
        Reconfigure key vectors by moving them to new positions.
        
        Args:
            positions: Current positions of key vectors
            key_vectors: The actual key vectors
            requester_id: Identifier for the entity requesting reconfiguration
        
        Returns:
            Tuple of (new_positions, result_message)
        """
        if len(positions) != len(key_vectors):
            error_msg = f"Position and vector counts do not match: {len(positions)} positions, {len(key_vectors)} vectors"
            logger.error(error_msg)
            return positions, error_msg
        
        logger.info(f"Starting reconfiguration requested by '{requester_id}'")
        logger.info(f"Original positions: {positions}")
        
        # Create backup before reconfiguration if secure_storage is available
        if self.secure_storage and self.backup_dir:
            timestamp = int(time.time())
            backup_file = os.path.join(self.backup_dir, f"pre_reconfig_backup_{timestamp}.json")
            
            try:
                self.vector_db.save(backup_file)
                logger.info(f"Created pre-reconfiguration backup: {backup_file}")
            except Exception as e:
                logger.error(f"Error creating backup: {str(e)}")
        
        # Generate new positions
        new_positions = self.map_manager.generate_new_positions(
            exclude_positions=positions,
            count=len(positions)
        )
        
        logger.info(f"Generated new positions: {new_positions}")
        
        # Move vectors to new positions
        current_time = time.time()
        
        # First, store vectors at new positions
        for i, (vector, new_pos) in enumerate(zip(key_vectors, new_positions)):
            # Get metadata from old position
            old_metadata = self.vector_db.get_metadata(positions[i]) or {}
            
            # Update metadata for the new position
            new_metadata = old_metadata.copy()
            new_metadata.update({
                "is_key_vector": True,
                "last_reconfigured": current_time,
                "previous_position": positions[i],
                "reconfiguration_id": requester_id
            })
            
            # Store vector at new position
            self.vector_db.store_vector(new_pos, vector, new_metadata)
        
        # Then, replace old positions with noise (or marker vectors)
        for i, old_pos in enumerate(positions):
            # Generate noise vector
            noise_vector = np.random.uniform(0, 1, self.vector_db.dimensions)
            noise_vector = noise_vector / np.linalg.norm(noise_vector)  # Normalize
            
            # Store noise at old position with metadata marking it as replaced
            noise_metadata = {
                "is_noise": True,
                "replaced_at": current_time,
                "replacement_type": "reconfiguration",
                "moved_to": new_positions[i],
                "reconfiguration_id": requester_id
            }
            
            self.vector_db.store_vector(old_pos, noise_vector, noise_metadata)
        
        # Update the last reconfiguration time
        self.last_reconfiguration_time = current_time
        
        # Log the reconfiguration event
        self._log_reconfiguration_event(
            requester_id=requester_id,
            old_positions=positions,
            new_positions=new_positions,
            timestamp=current_time
        )
        
        logger.info(f"Reconfiguration complete. Moved {len(positions)} vectors to new positions.")
        
        return new_positions, "Reconfiguration successful"
    
    def scheduled_reconfiguration_check(self) -> Dict[str, Any]:
        """
        Perform a scheduled check to see if any known keys need reconfiguration.
        
        This method is typically called by a background process or scheduler.
        
        Returns:
            Dictionary with results of the check
        """
        if not hasattr(self.key_manager, 'get_all_managed_keys'):
            return {
                "status": "error",
                "error": "Key manager does not support listing managed keys"
            }
        
        # Get all keys managed by the key manager
        managed_keys = self.key_manager.get_all_managed_keys()
        
        reconfigured_keys = []
        errors = []
        
        for key_id, key_info in managed_keys.items():
            positions = key_info.get('positions', [])
            
            if not positions:
                continue
            
            try:
                # Check if reconfiguration is needed
                if self.check_reconfiguration_needed(positions):
                    # Retrieve key vectors
                    key_vectors = [self.vector_db.get_vector(pos) for pos in positions]
                    
                    # Perform reconfiguration
                    new_positions, result = self.reconfigure(
                        positions=positions,
                        key_vectors=key_vectors,
                        requester_id=f"scheduled_{key_id}"
                    )
                    
                    # Update key manager with new positions
                    self.key_manager.update_key_positions(key_id, new_positions)
                    
                    reconfigured_keys.append({
                        "key_id": key_id,
                        "old_positions": positions,
                        "new_positions": new_positions
                    })
            except Exception as e:
                errors.append({
                    "key_id": key_id,
                    "error": str(e)
                })
        
        return {
            "status": "completed",
            "reconfigured_keys": reconfigured_keys,
            "errors": errors,
            "timestamp": time.time()
        }
    
    def _log_reconfiguration_event(
        self,
        requester_id: str,
        old_positions: List[int],
        new_positions: List[int],
        timestamp: float
    ) -> None:
        """
        Log a reconfiguration event to the audit log.
        
        Args:
            requester_id: Identifier for the entity requesting reconfiguration
            old_positions: Original positions before reconfiguration
            new_positions: New positions after reconfiguration
            timestamp: Time of the reconfiguration
        """
        if not self.audit_log_file:
            return
        
        # Create the log entry
        log_entry = {
            "timestamp": timestamp,
            "requester_id": requester_id,
            "event_type": "reconfiguration",
            "old_positions": old_positions,
            "new_positions": new_positions,
            "vector_count": len(old_positions),
            # Add a hash for integrity verification
            "event_hash": hashlib.sha256(f"{timestamp}|{requester_id}|{old_positions}|{new_positions}".encode()).hexdigest()
        }
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.audit_log_file), exist_ok=True)
            
            # Load existing log if it exists
            existing_log = []
            if os.path.exists(self.audit_log_file):
                with open(self.audit_log_file, 'r') as f:
                    existing_log = json.load(f)
            
            # Append new entry
            existing_log.append(log_entry)
            
            # Write updated log
            with open(self.audit_log_file, 'w') as f:
                json.dump(existing_log, f, indent=2)
            
            logger.debug(f"Reconfiguration event logged to {self.audit_log_file}")
        except Exception as e:
            logger.error(f"Error logging reconfiguration event: {str(e)}")

if __name__ == "__main__":
    # Example usage
    from vector_db import VectorDatabase
    from key_manager import QuantumResistantKeyManager
    from map_manager import MapManager
    
    # Create vector database
    vector_db = VectorDatabase(dimensions=100, size=1000)
    
    # Create map manager
    map_manager = MapManager(
        master_password="example_password",
        vector_db_size=vector_db.size,
        key_length=8
    )
    
    # Create key manager
    key_manager = QuantumResistantKeyManager(
        vector_db=vector_db,
        key_length=8,
        enable_reconfiguration=True,
        map_manager=map_manager
    )
    
    # Create controller
    controller = ReconfigurationController(
        vector_db=vector_db,
        key_manager=key_manager,
        map_manager=map_manager,
        reconfiguration_interval=3600,  # 1 hour
        backup_dir="./backups",
        audit_log_file="reconfig_audit.json"
    )
    
    print("ReconfigurationController initialized")
    print(f"Reconfiguration interval: {controller.reconfiguration_interval} seconds") 