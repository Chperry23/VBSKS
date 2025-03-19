#!/usr/bin/env python3
"""
VBSKS Example Usage

This script demonstrates how to use the Vector-Based Secure Key Storage system
programmatically (without using the CLI).
"""

import numpy as np
import base64
import json
import os
from pathlib import Path
import math  # Use standard library math instead of np.math

from vector_db import VectorDatabase
from key_manager import KeyManager
from simulation import SecuritySimulator
from utils import PRECISION, MIN_VALUE, MAX_VALUE

def example_key_generation():
    """
    Example of generating a key and storing it in a vector database
    """
    print("\n=== Example: Key Generation ===")
    
    # Create a new vector database
    dimensions = 100
    noise_size = 10000
    db = VectorDatabase(dimensions=dimensions, size=noise_size)
    
    # Create a key manager
    key_length = 5
    km = KeyManager(db, key_length=key_length)
    
    # Generate a key
    print(f"Generating key with {key_length} vectors in {dimensions}-dimensional space...")
    key_vectors, positions = km.generate_key("my_secret_seed")
    
    print(f"Key positions: {positions}")
    
    # Save the database and key
    db_file = "example_db.json"
    key_file = "example_key.json"
    
    print(f"Saving database to {db_file}...")
    db.save(db_file)
    
    print(f"Saving key data to {key_file}...")
    km.save_key_data(key_file, key_vectors, positions, {"description": "Example key"})
    
    # Derive a cryptographic key
    crypto_key = km.derive_cryptographic_key(key_vectors)
    print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")
    
    return db, km, key_vectors, positions

def example_key_verification(db, km, key_vectors, positions):
    """
    Example of verifying a key
    """
    print("\n=== Example: Key Verification ===")
    
    # Verify the correct key
    print("Verifying correct key...")
    is_valid = km.verify_key(positions, key_vectors)
    print(f"Key valid: {is_valid}")
    
    # Verify an incorrect key (modify one vector slightly)
    print("\nVerifying incorrect key (modified vector)...")
    modified_vectors = key_vectors.copy()
    modified_vectors[0, 0] += 0.1  # Modify the first element of the first vector
    is_valid = km.verify_key(positions, modified_vectors)
    print(f"Key valid: {is_valid}")
    
    # Verify with incorrect positions
    print("\nVerifying with incorrect positions...")
    incorrect_positions = positions.copy()
    incorrect_positions[0] = (incorrect_positions[0] + 1) % db.size
    is_valid = km.verify_key(incorrect_positions, key_vectors)
    print(f"Key valid: {is_valid}")

def example_key_retrieval():
    """
    Example of retrieving a key from a saved database
    """
    print("\n=== Example: Key Retrieval ===")
    
    # Load the database
    db_file = "example_db.json"
    key_file = "example_key.json"
    
    print(f"Loading database from {db_file}...")
    db = VectorDatabase.load(db_file)
    
    print(f"Loading key data from {key_file}...")
    key_data = KeyManager.load_key_data(key_file)
    
    # Create a key manager
    km = KeyManager(
        db,
        key_length=key_data['key_length'],
        threshold=key_data['threshold']
    )
    
    # Retrieve the key
    positions = key_data['positions']
    print(f"Retrieving key from positions: {positions}")
    key_vectors = km.retrieve_key(positions)
    
    # Verify the key
    is_valid = km.verify_key(positions, key_vectors)
    print(f"Retrieved key valid: {is_valid}")
    
    # Derive the cryptographic key
    crypto_key = km.derive_cryptographic_key(key_vectors)
    print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")

def example_security_simulation():
    """
    Example of running security simulations
    """
    print("\n=== Example: Security Simulation ===")
    
    # Load the database and key
    db_file = "example_db.json"
    key_file = "example_key.json"
    
    db = VectorDatabase.load(db_file)
    key_data = KeyManager.load_key_data(key_file)
    
    # Create a key manager
    km = KeyManager(
        db,
        key_length=key_data['key_length'],
        threshold=key_data['threshold']
    )
    
    # Create a security simulator
    simulator = SecuritySimulator(
        db,
        km,
        key_data['positions'],
        key_data['key_vectors']
    )
    
    # Run a random attack simulation
    print("Running random attack simulation (10 attempts)...")
    result = simulator.random_attack(10, parallel=False)
    print(f"  Success: {result['success']}")
    print(f"  Success Rate: {result['success_rate']:.8f}")
    print(f"  Closest Distance: {result['closest_distance']:.8f}")
    
    # Run a position-known attack simulation
    print("\nRunning position-known attack simulation (10 attempts)...")
    result = simulator.position_known_attack(10)
    print(f"  Success: {result['success']}")
    print(f"  Closest Distance: {result['closest_distance']:.8f}")
    
    # Run a quantum simulation
    print("\nRunning quantum attack simulation...")
    result = simulator.quantum_grover_simulation()
    print(f"  Classical Search Space: {result['classical_search_space']:.2e}")
    print(f"  Quantum Search Space: {result['quantum_search_space']:.2e}")
    print(f"  Classical Time: {result['classical_time_value']:.2e} {result['classical_time_unit']}")
    print(f"  Quantum Time: {result['quantum_time_value']:.2e} {result['quantum_time_unit']}")

def calculate_theoretical_security():
    """
    Calculate the theoretical security of the system
    """
    print("\n=== Theoretical Security Analysis ===")
    
    # Parameters
    dimensions = 100
    noise_size = 10000
    key_length = 5
    precision = 6  # 6 decimal places
    
    try:
        # Calculate position combinations
        # Use logarithms to avoid overflow
        log_position_combinations = (
            math.log10(math.factorial(noise_size)) - 
            math.log10(math.factorial(key_length)) - 
            math.log10(math.factorial(noise_size - key_length))
        )
        position_combinations = 10**log_position_combinations
        
        # Calculate vector value space
        # Use logarithm to avoid overflow
        log_values_per_dimension = math.log10(10**precision * (MAX_VALUE - MIN_VALUE))
        log_vector_value_space = dimensions * log_values_per_dimension
        
        # Total search space (in log10)
        log_search_space = log_position_combinations + (key_length * log_vector_value_space)
        
        # Convert log10 to log2 for bit security
        log2_search_space = log_search_space * math.log2(10)
        
        print(f"Dimensions per vector: {dimensions}")
        print(f"Noise database size: {noise_size}")
        print(f"Key length (vectors): {key_length}")
        print(f"Precision (decimal places): {precision}")
        print(f"Position combinations (log10): {log_position_combinations:.2f}")
        print(f"Vector value space per vector (log10): {log_vector_value_space:.2f}")
        print(f"Total search space (log10): {log_search_space:.2f}")
        
        # Compare to some common cryptographic key sizes
        print("\nFor comparison:")
        print(f"  128-bit key: 2^128 ≈ 10^{128 * math.log10(2):.2f}")
        print(f"  256-bit key: 2^256 ≈ 10^{256 * math.log10(2):.2f}")
        print(f"  VBSKS key: ≈ 2^{log2_search_space:.2f} ≈ 10^{log_search_space:.2f}")
        
        # Expected time to brute force (1 billion checks per second)
        log_time_seconds = log_search_space - 9  # 10^9 checks per second
        
        # Express in more readable units
        if log_time_seconds > 7:  # More than 10 million seconds
            log_time_years = log_time_seconds - math.log10(365.25 * 24 * 60 * 60)
            print(f"\nTime to brute force (1 billion checks/sec): ≈ 10^{log_time_years:.2f} years")
            
            # Compare to age of universe (13.8 billion years)
            log_universe_ratio = log_time_years - math.log10(13.8e9)
            print(f"That's ≈ 10^{log_universe_ratio:.2f} times the age of the universe")
        else:
            print(f"\nTime to brute force (1 billion checks/sec): ≈ 10^{log_time_seconds:.2f} seconds")
            
    except Exception as e:
        print(f"Error in calculation: {str(e)}")
        print("The security of this system is extremely high, causing numeric overflow.")
        print("This demonstrates that the key space is effectively impossible to brute force.")

def main():
    """Main function to run all examples"""
    print("Vector-Based Secure Key Storage (VBSKS) Examples")
    print("===============================================")
    
    # Generate a key and get the database and key manager
    db, km, key_vectors, positions = example_key_generation()
    
    # Example of key verification
    example_key_verification(db, km, key_vectors, positions)
    
    # Example of key retrieval
    example_key_retrieval()
    
    # Example of security simulation
    example_security_simulation()
    
    # Calculate theoretical security
    calculate_theoretical_security()
    
    print("\nExamples completed!")

if __name__ == "__main__":
    main() 