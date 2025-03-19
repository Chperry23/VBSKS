#!/usr/bin/env python3
"""
Vector-Based Secure Key Storage (VBSKS)

A quantum-resistant key storage system that leverages a noise-filled,
high-dimensional vector space to securely store cryptographic keys.

Usage:
    python vbsks.py generate [options]
    python vbsks.py retrieve [options]
    python vbsks.py simulate [options]
    python vbsks.py db secure-save [options]
    python vbsks.py db secure-load [options]
"""

import argparse
import sys
import os
import json
import numpy as np
import base64
from pathlib import Path

from vector_db import VectorDatabase
from key_manager import KeyManager, QuantumResistantKeyManager
from simulation import SecuritySimulator
from utils import PRECISION

def generate_command(args):
    """
    Generate a new key and vector database
    
    Args:
        args: Command-line arguments
    """
    print(f"Generating vector database with {args.dimensions} dimensions and {args.noise_size} vectors...")
    
    # Create a new vector database
    vector_db = VectorDatabase(
        dimensions=args.dimensions,
        size=args.noise_size,
        threshold=args.threshold,
        use_indexing=args.use_indexing
    )
    
    # Determine whether to use enhanced security
    use_quantum_resistant = args.enhanced_security
    
    # Create a key manager
    if use_quantum_resistant:
        key_manager = QuantumResistantKeyManager(
            vector_db=vector_db,
            key_length=args.key_length,
            threshold=args.threshold,
            quantum_algorithm=args.quantum_algorithm
        )
    else:
        key_manager = KeyManager(
            vector_db=vector_db,
            key_length=args.key_length,
            threshold=args.threshold
        )
    
    # Generate a key
    print(f"Generating key with {args.key_length} vectors...")
    key_vectors, positions = key_manager.generate_key(args.secret_seed)
    
    # Derive a cryptographic key if requested
    if args.derive_key:
        crypto_key = key_manager.derive_cryptographic_key(key_vectors)
        print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")
    
    # Save the database
    if args.db_output:
        print(f"Saving vector database to {args.db_output}...")
        vector_db.save(args.db_output)
    
    # Save the key data with appropriate security
    if args.key_output:
        if use_quantum_resistant:
            print(f"Saving quantum-resistant key data to {args.key_output}...")
            result = key_manager.save_key_data_secure(
                filename=args.key_output,
                key_vectors=key_vectors,
                positions=positions,
                metadata={"description": args.description} if args.description else None,
                use_quantum_resistant=True,
                split_shares=args.split_shares,
                threshold=args.threshold_shares,
                encryption_password=args.encryption_password
            )
            
            # Print information about the saved files
            if args.split_shares > 1:
                print(f"Split key into {args.split_shares} shares (threshold: {args.threshold_shares}).")
                print("Share files:")
                for key, file in result['files'].items():
                    if key.startswith('share_'):
                        print(f"  {file}")
                if 'recovery_info' in result['files']:
                    print(f"Recovery info: {result['files']['recovery_info']}")
            else:
                print(f"Saved quantum-resistant key data to {args.key_output}")
                
            if args.encryption_password:
                print("The key is password-protected. You'll need this password to retrieve the key.")
        else:
            print(f"Saving standard key data to {args.key_output}...")
            key_manager.save_key_data(
                args.key_output,
                key_vectors,
                positions,
                metadata={"description": args.description} if args.description else None
            )
    
    # Print key information
    print("\nKey Generation Summary:")
    print(f"  Dimensions: {args.dimensions}")
    print(f"  Noise Size: {args.noise_size}")
    print(f"  Key Length: {args.key_length}")
    print(f"  Threshold: {args.threshold}")
    print(f"  Key Positions: {positions}")
    if use_quantum_resistant:
        print(f"  Enhanced Security: Yes (Algorithm: {args.quantum_algorithm})")
        if args.split_shares > 1:
            print(f"  Secret Sharing: {args.split_shares} shares (threshold: {args.threshold_shares})")
        if args.encryption_password:
            print(f"  Password Protection: Yes")
    
    return 0

def retrieve_command(args):
    """
    Retrieve a key from a vector database
    
    Args:
        args: Command-line arguments
    """
    # Load the vector database
    print(f"Loading vector database from {args.db_input}...")
    vector_db = VectorDatabase.load(args.db_input)
    
    # Determine whether to use enhanced security
    use_quantum_resistant = args.enhanced_security or args.share_files or \
                           args.recovery_info or args.encryption_password
    
    if args.key_data or args.recovery_info or args.share_files:
        # Check if it's a recovery info file
        is_recovery_file = args.key_data.endswith('.recovery_info') if args.key_data else False
        
        if use_quantum_resistant:
            # Use quantum-resistant key manager
            key_manager = QuantumResistantKeyManager(
                vector_db=vector_db,
                quantum_algorithm=args.quantum_algorithm
            )
            
            # Handle different key data sources
            if is_recovery_file or args.recovery_info:
                recovery_file = args.recovery_info if args.recovery_info else args.key_data
                print(f"Loading recovery info from {recovery_file}...")
                # Load the key data using the recovery info
                key_data = QuantumResistantKeyManager.load_key_data_secure(
                    source=recovery_file,
                    encryption_password=args.encryption_password
                )
            elif args.share_files:
                # Load from share files
                print(f"Loading key from {len(args.share_files)} share files...")
                key_data = QuantumResistantKeyManager.load_key_data_secure(
                    source=args.share_files,
                    encryption_password=args.encryption_password
                )
            else:
                # Load from single key file
                print(f"Loading quantum-resistant key data from {args.key_data}...")
                key_data = QuantumResistantKeyManager.load_key_data_secure(
                    source=args.key_data,
                    encryption_password=args.encryption_password
                )
                
            # Update the key manager with the correct dimensions
            key_manager = QuantumResistantKeyManager(
                vector_db=vector_db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION),
                quantum_algorithm=args.quantum_algorithm
            )
        else:
            # Load standard key data from file
            print(f"Loading key data from {args.key_data}...")
            key_data = KeyManager.load_key_data(args.key_data)
            
            # Create a key manager
            key_manager = KeyManager(
                vector_db=vector_db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION)
            )
        
        # Verify the key
        if args.vectors_input:
            # Load vectors from file
            print(f"Loading input vectors from {args.vectors_input}...")
            with open(args.vectors_input, 'r') as f:
                data = json.load(f)
                input_vectors = np.array(data['vectors'])
            
            # Verify the key
            is_valid = key_manager.verify_key(key_data['positions'], input_vectors)
            print(f"Key verification result: {'VALID' if is_valid else 'INVALID'}")
            
            # Derive a cryptographic key if requested
            if is_valid and args.derive_key:
                crypto_key = key_manager.derive_cryptographic_key(input_vectors)
                print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")
            
            return 0 if is_valid else 1
        else:
            # Retrieve the key
            key_vectors = key_manager.retrieve_key(key_data['positions'])
            
            # Save the key vectors if requested
            if args.vectors_output:
                print(f"Saving key vectors to {args.vectors_output}...")
                with open(args.vectors_output, 'w') as f:
                    json.dump({
                        'vectors': key_vectors.tolist(),
                        'shape': key_vectors.shape
                    }, f, indent=2)
            
            # Derive a cryptographic key if requested
            if args.derive_key:
                crypto_key = key_manager.derive_cryptographic_key(key_vectors)
                print(f"Derived cryptographic key: {base64.b64encode(crypto_key).decode()}")
            
            return 0
    else:
        print("Error: Either --key-data, --recovery-info, or --share-files must be provided")
        return 1

def simulate_command(args):
    """
    Run security simulations
    
    Args:
        args: Command-line arguments
    """
    if args.db_input and args.key_data:
        # Load the vector database and key data
        print(f"Loading vector database from {args.db_input}...")
        vector_db = VectorDatabase.load(args.db_input)
        
        # Determine whether to use enhanced security
        use_quantum_resistant = args.enhanced_security or args.key_data.endswith('.recovery_info')
        
        if use_quantum_resistant:
            # Load quantum-resistant key data
            print(f"Loading quantum-resistant key data from {args.key_data}...")
            key_data = QuantumResistantKeyManager.load_key_data_secure(
                source=args.key_data,
                encryption_password=args.encryption_password
            )
            
            # Create a key manager
            key_manager = QuantumResistantKeyManager(
                vector_db=vector_db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION),
                quantum_algorithm=args.quantum_algorithm
            )
        else:
            # Load standard key data
            print(f"Loading key data from {args.key_data}...")
            key_data = KeyManager.load_key_data(args.key_data)
            
            # Create a key manager
            key_manager = KeyManager(
                vector_db=vector_db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION)
            )
        
        # Create a security simulator
        simulator = SecuritySimulator(
            vector_db,
            key_manager,
            key_data['positions'],
            key_data['key_vectors']
        )
        
        # Run simulations
        if args.random_attempts > 0:
            print(f"Running random attack simulation with {args.random_attempts} attempts...")
            result = simulator.random_attack(args.random_attempts, parallel=not args.no_parallel)
            print(f"  Success: {result['success']}")
            print(f"  Success Rate: {result['success_rate']:.8f}")
            print(f"  Closest Distance: {result['closest_distance']:.8f}")
            print(f"  Time: {result['elapsed_time']:.2f} seconds")
        
        if args.position_known_attempts > 0:
            print(f"Running position-known attack with {args.position_known_attempts} attempts...")
            result = simulator.position_known_attack(args.position_known_attempts)
            print(f"  Success: {result['success']}")
            print(f"  Closest Distance: {result['closest_distance']:.8f}")
            print(f"  Time: {result['elapsed_time']:.2f} seconds")
        
        if args.quantum:
            print("Running quantum attack simulation...")
            result = simulator.quantum_grover_simulation()
            print(f"  Classical Search Space: {result['classical_search_space']:.2e}")
            print(f"  Quantum Search Space: {result['quantum_search_space']:.2e}")
            print(f"  Classical Time: {result['classical_time_value']:.2e} {result['classical_time_unit']}")
            print(f"  Quantum Time: {result['quantum_time_value']:.2e} {result['quantum_time_unit']}")
        
        # Save results
        if args.output:
            print(f"Saving results to {args.output}...")
            simulator.save_results(args.output)
        
        # Plot results
        if args.plot or args.show_plot:
            if args.plot:
                print(f"Saving plot to {args.plot}...")
                simulator.plot_attack_results(args.plot)
            else:
                print("Showing plot...")
                simulator.plot_attack_results()
        
        return 0
    else:
        # Generate a new database and key for simulation
        print("Generating a new database and key for simulation...")
        
        # Create a new vector database
        vector_db = VectorDatabase(
            dimensions=args.dimensions,
            size=args.noise_size,
            threshold=args.threshold
        )
        
        # Determine whether to use enhanced security
        use_quantum_resistant = args.enhanced_security
        
        # Create a key manager
        if use_quantum_resistant:
            key_manager = QuantumResistantKeyManager(
                vector_db=vector_db,
                key_length=args.key_length,
                threshold=args.threshold,
                quantum_algorithm=args.quantum_algorithm
            )
        else:
            key_manager = KeyManager(
                vector_db=vector_db,
                key_length=args.key_length,
                threshold=args.threshold
            )
        
        # Generate a key
        key_vectors, positions = key_manager.generate_key("simulation_seed")
        
        # Create a security simulator
        simulator = SecuritySimulator(
            vector_db,
            key_manager,
            positions,
            key_vectors
        )
        
        # Run simulations
        if args.random_attempts > 0:
            print(f"Running random attack simulation with {args.random_attempts} attempts...")
            result = simulator.random_attack(args.random_attempts, parallel=not args.no_parallel)
            print(f"  Success: {result['success']}")
            print(f"  Success Rate: {result['success_rate']:.8f}")
            print(f"  Closest Distance: {result['closest_distance']:.8f}")
            print(f"  Time: {result['elapsed_time']:.2f} seconds")
        
        if args.position_known_attempts > 0:
            print(f"Running position-known attack with {args.position_known_attempts} attempts...")
            result = simulator.position_known_attack(args.position_known_attempts)
            print(f"  Success: {result['success']}")
            print(f"  Closest Distance: {result['closest_distance']:.8f}")
            print(f"  Time: {result['elapsed_time']:.2f} seconds")
        
        if args.quantum:
            print("Running quantum attack simulation...")
            result = simulator.quantum_grover_simulation()
            print(f"  Classical Search Space: {result['classical_search_space']:.2e}")
            print(f"  Quantum Search Space: {result['quantum_search_space']:.2e}")
            print(f"  Classical Time: {result['classical_time_value']:.2e} {result['classical_time_unit']}")
            print(f"  Quantum Time: {result['quantum_time_value']:.2e} {result['quantum_time_unit']}")
        
        # Save results
        if args.output:
            print(f"Saving results to {args.output}...")
            simulator.save_results(args.output)
        
        # Plot results
        if args.plot or args.show_plot:
            if args.plot:
                print(f"Saving plot to {args.plot}...")
                simulator.plot_attack_results(args.plot)
            else:
                print("Showing plot...")
                simulator.plot_attack_results()
        
        return 0

def db_secure_save_command(args):
    """
    Securely save a vector database with enhanced security features
    
    Args:
        args: Command-line arguments
    """
    print("Saving secure vector database...")
    
    # Create a new database or load existing one
    if args.dimensions and args.size:
        print(f"Creating new vector database with {args.dimensions} dimensions and {args.size} vectors...")
        vector_db = VectorDatabase(
            dimensions=args.dimensions,
            size=args.size,
            threshold=args.threshold,
            use_indexing=args.use_indexing
        )
    elif args.db_input:
        print(f"Loading existing database from {args.db_input}...")
        vector_db = VectorDatabase.load(args.db_input)
    else:
        print("Error: Must provide either --dimensions and --size, or --db-input")
        return 1
    
    print(f"Saving with enhanced security to {args.output}...")
    
    # Apply secure save
    try:
        result = vector_db.save_secure(
            filename=args.output,
            split_shares=args.split_shares,
            threshold_shares=args.threshold_shares,
            encryption_password=args.encryption_password,
            add_statistical_noise=args.add_noise,
            sign_data=args.sign_data
        )
        
        # Print information about the saved files
        print("\nDatabase Save Summary:")
        print(f"  Dimensions: {vector_db.dimensions}")
        print(f"  Size: {vector_db.size}")
        print(f"  Password protected: {'Yes' if args.encryption_password else 'No'}")
        print(f"  Statistical noise: {'Added' if args.add_noise else 'Not added'}")
        print(f"  Digital signature: {'Added' if args.sign_data else 'Not added'}")
        
        if args.split_shares > 1:
            print(f"\nSplit into {args.split_shares} shares (threshold: {args.threshold_shares}).")
            print("Share files:")
            for i in range(args.split_shares):
                share_file = f"{args.output}.share{i+1}"
                print(f"  {share_file}")
            print(f"Recovery info: {args.output}.recovery_info")
            print("\nTo load the database using shares:")
            print(f"  python vbsks.py db secure-load --share-files {args.output}.share1 {args.output}.share2 --encryption-password [YOUR-PASSWORD]")
            print("\nTo load using recovery info:")
            print(f"  python vbsks.py db secure-load --recovery-info {args.output}.recovery_info --encryption-password [YOUR-PASSWORD]")
        else:
            print(f"\nSaved secure database to {args.output}")
            if args.encryption_password:
                print("\nTo load the database:")
                print(f"  python vbsks.py db secure-load --db-input {args.output} --encryption-password [YOUR-PASSWORD]")
        
        return 0
    except Exception as e:
        print(f"Error saving secure database: {str(e)}")
        return 1

def db_secure_load_command(args):
    """
    Securely load a vector database with enhanced security features
    
    Args:
        args: Command-line arguments
    """
    print("Loading secure vector database...")
    
    try:
        # Load the database securely
        vector_db, result_info = VectorDatabase.load_secure(
            filename=args.db_input,
            recovery_info_file=args.recovery_info,
            share_files=args.share_files,
            encryption_password=args.encryption_password,
            verify_signature=not args.skip_signature_verification
        )
        
        # Print database information
        print("\nDatabase Information:")
        print(f"  Dimensions: {vector_db.dimensions}")
        print(f"  Size: {vector_db.size}")
        print(f"  Threshold: {vector_db.threshold}")
        print(f"  Use indexing: {vector_db.use_indexing}")
        
        # Print security information
        print("\nSecurity Information:")
        print(f"  Password protected: {'Yes' if result_info.get('password_protected', False) else 'No'}")
        print(f"  PQC protected: {'Yes' if result_info.get('pqc_protected', False) else 'No'}")
        
        if result_info.get('signed', False):
            verification = result_info.get('signature_verified', False)
            print(f"  Digital signature: {'Valid' if verification else 'INVALID'}")
            if not verification:
                print("  WARNING: Signature verification failed! The database may be corrupted or tampered with.")
        
        # Save in standard format if requested
        if args.output:
            print(f"Saving database to standard format at {args.output}...")
            vector_db.save(args.output)
        
        return 0
    except ValueError as e:
        print(f"Error loading secure database: {str(e)}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return 1

def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(
        description="Vector-Based Secure Key Storage (VBSKS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        help="Command to execute"
    )
    
    # Generate command
    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a new key and vector database"
    )
    generate_parser.add_argument(
        "--dimensions", type=int, default=100,
        help="Number of dimensions for each vector"
    )
    generate_parser.add_argument(
        "--noise-size", type=int, default=10000,
        help="Size of the noise database"
    )
    generate_parser.add_argument(
        "--key-length", type=int, default=5,
        help="Number of vectors in the key"
    )
    generate_parser.add_argument(
        "--threshold", type=float, default=PRECISION,
        help="Distance threshold for vector equality"
    )
    generate_parser.add_argument(
        "--use-indexing", action="store_true",
        help="Use FAISS indexing for faster retrieval"
    )
    generate_parser.add_argument(
        "--secret-seed", type=str, default=None,
        help="Secret seed for position derivation"
    )
    generate_parser.add_argument(
        "--db-output", type=str, default="db.json",
        help="Path to save the vector database"
    )
    generate_parser.add_argument(
        "--key-output", type=str, default="key.json",
        help="Path to save the key data"
    )
    generate_parser.add_argument(
        "--description", type=str,
        help="Description for the key"
    )
    generate_parser.add_argument(
        "--derive-key", action="store_true",
        help="Derive a cryptographic key from the vector-based key"
    )
    # Enhanced security options
    generate_parser.add_argument(
        "--enhanced-security", action="store_true",
        help="Use enhanced security features (quantum-resistant encryption)"
    )
    generate_parser.add_argument(
        "--quantum-algorithm", type=str, default="Simulate",
        help="Post-quantum algorithm to use (e.g., Kyber768, Simulate)"
    )
    generate_parser.add_argument(
        "--split-shares", type=int, default=1,
        help="Number of shares to split the key into (Shamir's Secret Sharing)"
    )
    generate_parser.add_argument(
        "--threshold-shares", type=int, default=1,
        help="Minimum number of shares needed for reconstruction"
    )
    generate_parser.add_argument(
        "--encryption-password", type=str,
        help="Optional password for additional encryption layer"
    )
    
    # Retrieve command
    retrieve_parser = subparsers.add_parser(
        "retrieve",
        help="Retrieve a key from a vector database"
    )
    retrieve_parser.add_argument(
        "--db-input", type=str, required=True,
        help="Path to the vector database"
    )
    retrieve_parser.add_argument(
        "--key-data", type=str,
        help="Path to the key data file"
    )
    retrieve_parser.add_argument(
        "--vectors-input", type=str,
        help="Path to the input vectors file for verification"
    )
    retrieve_parser.add_argument(
        "--vectors-output", type=str,
        help="Path to save the retrieved vectors"
    )
    retrieve_parser.add_argument(
        "--derive-key", action="store_true",
        help="Derive a cryptographic key from the vector-based key"
    )
    # Enhanced security options for retrieval
    retrieve_parser.add_argument(
        "--enhanced-security", action="store_true",
        help="Use enhanced security features (quantum-resistant encryption)"
    )
    retrieve_parser.add_argument(
        "--quantum-algorithm", type=str, default="Simulate",
        help="Post-quantum algorithm to use (e.g., Kyber768, Simulate)"
    )
    retrieve_parser.add_argument(
        "--encryption-password", type=str,
        help="Password for decrypting password-protected key"
    )
    retrieve_parser.add_argument(
        "--share-files", type=str, nargs="+",
        help="Paths to share files for reconstructing split key"
    )
    retrieve_parser.add_argument(
        "--recovery-info", type=str,
        help="Path to recovery info file for reconstructing split key"
    )
    
    # Simulate command
    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Run security simulations"
    )
    simulate_parser.add_argument(
        "--db-input", type=str,
        help="Path to the vector database"
    )
    simulate_parser.add_argument(
        "--key-data", type=str,
        help="Path to the key data file"
    )
    simulate_parser.add_argument(
        "--dimensions", type=int, default=100,
        help="Number of dimensions for each vector (if generating new data)"
    )
    simulate_parser.add_argument(
        "--noise-size", type=int, default=10000,
        help="Size of the noise database (if generating new data)"
    )
    simulate_parser.add_argument(
        "--key-length", type=int, default=5,
        help="Number of vectors in the key (if generating new data)"
    )
    simulate_parser.add_argument(
        "--threshold", type=float, default=PRECISION,
        help="Distance threshold for vector equality (if generating new data)"
    )
    simulate_parser.add_argument(
        "--random-attempts", type=int, default=1000,
        help="Number of random brute force attempts"
    )
    simulate_parser.add_argument(
        "--position-known-attempts", type=int, default=100,
        help="Number of position-known attempts"
    )
    simulate_parser.add_argument(
        "--quantum", action="store_true",
        help="Run quantum simulation"
    )
    simulate_parser.add_argument(
        "--no-parallel", action="store_true",
        help="Disable parallel processing"
    )
    simulate_parser.add_argument(
        "--output", type=str,
        help="Path to save results"
    )
    simulate_parser.add_argument(
        "--plot", type=str,
        help="Path to save plot"
    )
    simulate_parser.add_argument(
        "--show-plot", action="store_true",
        help="Show plot"
    )
    # Enhanced security options for simulation
    simulate_parser.add_argument(
        "--enhanced-security", action="store_true",
        help="Use enhanced security features (quantum-resistant encryption)"
    )
    simulate_parser.add_argument(
        "--quantum-algorithm", type=str, default="Simulate",
        help="Post-quantum algorithm to use (e.g., Kyber768, Simulate)"
    )
    simulate_parser.add_argument(
        "--encryption-password", type=str,
        help="Password for decrypting password-protected key"
    )
    
    # Database management command
    db_parser = subparsers.add_parser(
        "db",
        help="Database management operations"
    )
    db_subparsers = db_parser.add_subparsers(
        title="db_commands",
        dest="db_command",
        help="Database command to execute"
    )
    
    # Secure save command
    db_secure_save_parser = db_subparsers.add_parser(
        "secure-save",
        help="Save a vector database with enhanced security features"
    )
    # Input options
    db_secure_save_parser.add_argument(
        "--dimensions", type=int,
        help="Number of dimensions for new vector database"
    )
    db_secure_save_parser.add_argument(
        "--size", type=int,
        help="Size of new vector database"
    )
    db_secure_save_parser.add_argument(
        "--db-input", type=str,
        help="Path to existing vector database to secure"
    )
    db_secure_save_parser.add_argument(
        "--threshold", type=float, default=PRECISION,
        help="Distance threshold for vector equality"
    )
    db_secure_save_parser.add_argument(
        "--use-indexing", action="store_true",
        help="Use FAISS indexing for faster retrieval"
    )
    # Output options
    db_secure_save_parser.add_argument(
        "--output", type=str, required=True,
        help="Path to save the secure database"
    )
    # Security options
    db_secure_save_parser.add_argument(
        "--encryption-password", type=str,
        help="Password for encrypting the database"
    )
    db_secure_save_parser.add_argument(
        "--split-shares", type=int, default=1,
        help="Number of shares to split the database into"
    )
    db_secure_save_parser.add_argument(
        "--threshold-shares", type=int, default=1,
        help="Minimum number of shares needed for reconstruction"
    )
    db_secure_save_parser.add_argument(
        "--add-noise", action="store_true",
        help="Add statistical noise for additional security"
    )
    db_secure_save_parser.add_argument(
        "--sign-data", action="store_true", default=True,
        help="Add digital signature for integrity verification (default: True)"
    )
    
    # Secure load command
    db_secure_load_parser = db_subparsers.add_parser(
        "secure-load",
        help="Load a vector database with enhanced security features"
    )
    # Input options (mutually exclusive)
    db_input_group = db_secure_load_parser.add_mutually_exclusive_group(required=True)
    db_input_group.add_argument(
        "--db-input", type=str,
        help="Path to the secure database file"
    )
    db_input_group.add_argument(
        "--recovery-info", type=str,
        help="Path to recovery info file for reconstructing split database"
    )
    db_input_group.add_argument(
        "--share-files", type=str, nargs="+",
        help="Paths to share files for reconstructing split database"
    )
    # Security options
    db_secure_load_parser.add_argument(
        "--encryption-password", type=str,
        help="Password for decrypting the database"
    )
    db_secure_load_parser.add_argument(
        "--skip-signature-verification", action="store_true",
        help="Skip signature verification (not recommended)"
    )
    # Output options
    db_secure_load_parser.add_argument(
        "--output", type=str,
        help="Path to save the database in standard format"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Ensure a command was provided
    if not args.command:
        parser.print_help()
        return 1
    
    # Ensure a database command was provided if the main command is 'db'
    if args.command == "db" and not args.db_command:
        db_parser.print_help()
        return 1
    
    # Handle secret seed
    if args.command == "generate" and not args.secret_seed:
        # Generate a random secret seed
        args.secret_seed = os.urandom(16).hex()
    
    # Validate threshold shares
    if args.command == "generate" and args.split_shares > 1:
        if args.threshold_shares < 1 or args.threshold_shares > args.split_shares:
            print(f"Error: threshold-shares must be between 1 and {args.split_shares}")
            return 1
    
    # Execute the appropriate command
    if args.command == "generate":
        return generate_command(args)
    elif args.command == "retrieve":
        return retrieve_command(args)
    elif args.command == "simulate":
        return simulate_command(args)
    elif args.command == "db":
        if args.db_command == "secure-save":
            return db_secure_save_command(args)
        elif args.db_command == "secure-load":
            return db_secure_load_command(args)
        else:
            db_parser.print_help()
            return 1
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 