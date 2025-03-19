"""
Simulation module for VBSKS

This module provides tools to simulate attacks against the VBSKS system
and evaluate its security.
"""

import numpy as np
import time
import tqdm
import matplotlib.pyplot as plt
from typing import List, Tuple, Dict, Any, Optional, Union
import json
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import os
from datetime import datetime

from utils import (
    generate_random_vector,
    euclidean_distance,
    quantize_vector,
    PRECISION,
    MIN_VALUE,
    MAX_VALUE
)
from vector_db import VectorDatabase
from key_manager import KeyManager

class SecuritySimulator:
    """
    Simulates various attacks on the VBSKS system to evaluate security.
    """
    
    def __init__(
        self,
        vector_db: VectorDatabase,
        key_manager: KeyManager,
        key_positions: List[int],
        key_vectors: np.ndarray
    ):
        """
        Initialize the security simulator
        
        Args:
            vector_db: Vector database containing the key
            key_manager: Key manager instance
            key_positions: Positions of the key vectors
            key_vectors: The key vectors
        """
        self.vector_db = vector_db
        self.key_manager = key_manager
        self.key_positions = key_positions
        self.key_vectors = key_vectors
        self.results = []
    
    def random_attack(self, attempts: int, parallel: bool = True) -> Dict[str, Any]:
        """
        Simulate a random brute-force attack
        
        Args:
            attempts: Number of random attempts to make
            parallel: Whether to use parallel processing
            
        Returns:
            Dictionary with results
        """
        start_time = time.time()
        success = False
        closest_distance = float('inf')
        dimensions = self.vector_db.dimensions
        key_length = self.key_manager.key_length
        
        def _single_attempt(i: int) -> Tuple[bool, float, List[int], np.ndarray]:
            # Generate random positions
            random_positions = np.random.choice(
                self.vector_db.size, key_length, replace=False
            ).tolist()
            
            # Generate random key vectors
            random_vectors = np.zeros((key_length, dimensions))
            for j in range(key_length):
                random_vectors[j] = generate_random_vector(dimensions)
            
            # Quantize the vectors
            random_vectors = quantize_vector(random_vectors)
            
            # Check if positions match
            positions_match = set(random_positions) == set(self.key_positions)
            
            # Calculate minimum distance to actual key vectors
            min_distance = float('inf')
            if positions_match:
                for j in range(key_length):
                    idx_real = self.key_positions.index(random_positions[j])
                    dist = euclidean_distance(random_vectors[j], self.key_vectors[idx_real])
                    min_distance = min(min_distance, dist)
            
            # Check if the key is valid
            is_valid = self.key_manager.verify_key(random_positions, random_vectors)
            
            return is_valid, min_distance, random_positions, random_vectors
        
        results = []
        if parallel and attempts > 10:
            # Use parallel processing for large numbers of attempts
            num_cores = max(1, multiprocessing.cpu_count() - 1)
            with ProcessPoolExecutor(max_workers=num_cores) as executor:
                results = list(tqdm.tqdm(
                    executor.map(_single_attempt, range(attempts)),
                    total=attempts,
                    desc="Brute Force Attack Simulation"
                ))
        else:
            # Sequential processing
            for i in tqdm.tqdm(range(attempts), desc="Brute Force Attack Simulation"):
                results.append(_single_attempt(i))
        
        # Process results
        successes = [r for r in results if r[0]]
        success = len(successes) > 0
        if successes:
            closest_distance = min(r[1] for r in successes)
        else:
            # Handle case when there are no finite distances
            finite_distances = [r[1] for r in results if r[1] != float('inf')]
            if finite_distances:
                closest_distance = min(finite_distances)
            # If no finite distances, keep closest_distance as float('inf')
        
        elapsed_time = time.time() - start_time
        
        result = {
            'attack_type': 'random',
            'attempts': attempts,
            'success': success,
            'success_rate': len(successes) / attempts if attempts > 0 else 0,
            'closest_distance': closest_distance,
            'elapsed_time': elapsed_time,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results.append(result)
        return result
    
    def position_known_attack(self, attempts: int) -> Dict[str, Any]:
        """
        Simulate an attack where the key positions are known
        
        Args:
            attempts: Number of random attempts to make
            
        Returns:
            Dictionary with results
        """
        start_time = time.time()
        success = False
        closest_distance = float('inf')
        dimensions = self.vector_db.dimensions
        key_length = self.key_manager.key_length
        
        all_distances = []  # Store all distances for reporting
        
        for i in tqdm.tqdm(range(attempts), desc="Position-Known Attack Simulation"):
            # Generate random key vectors with the correct positions
            random_vectors = np.zeros((key_length, dimensions))
            for j in range(key_length):
                random_vectors[j] = generate_random_vector(dimensions)
            
            # Quantize the vectors
            random_vectors = quantize_vector(random_vectors)
            
            # Calculate minimum distance to actual key vectors
            min_distance = float('inf')
            for j in range(key_length):
                dist = euclidean_distance(random_vectors[j], self.key_vectors[j])
                min_distance = min(min_distance, dist)
            
            # Keep track of the closest we've gotten
            if min_distance < closest_distance:
                closest_distance = min_distance
            
            # Record distance for reporting
            all_distances.append(min_distance)
            
            # Check if the key is valid
            is_valid = self.key_manager.verify_key(self.key_positions, random_vectors)
            if is_valid:
                success = True
                break
        
        elapsed_time = time.time() - start_time
        
        result = {
            'attack_type': 'position_known',
            'attempts': attempts,
            'success': success,
            'closest_distance': closest_distance,
            'elapsed_time': elapsed_time,
            'all_distances': all_distances,  # Include all distances for analysis
            'timestamp': datetime.now().isoformat()
        }
        
        self.results.append(result)
        return result
    
    def quantum_grover_simulation(self, quantum_speedup_factor: int = 2) -> Dict[str, Any]:
        """
        Simulate a quantum attack using Grover's algorithm
        
        This is a theoretical simulation that estimates the search space reduction
        that would be achieved by Grover's algorithm.
        
        Args:
            quantum_speedup_factor: The reduction in search space (typically sqrt)
            
        Returns:
            Dictionary with results
        """
        dimensions = self.vector_db.dimensions
        key_length = self.key_manager.key_length
        noise_size = self.vector_db.size
        
        try:
            # Calculate classical search space
            position_combinations = np.math.factorial(noise_size) / (
                np.math.factorial(key_length) * np.math.factorial(noise_size - key_length)
            )
            
            # Estimate vector value space (assuming each dimension has 10^precision values)
            precision = 6  # 6 decimal places
            values_per_dimension = 10**precision * (MAX_VALUE - MIN_VALUE)
            vector_value_space = values_per_dimension**dimensions
            
            # Total classical search space
            classical_search_space = position_combinations * (vector_value_space**key_length)
            
            # Reduced search space with Grover's algorithm
            quantum_search_space = classical_search_space**(1/quantum_speedup_factor)
            
            # Theoretical time for classical brute force (assuming 1 billion checks per second)
            classical_time_seconds = classical_search_space / 1e9
            quantum_time_seconds = quantum_search_space / 1e9
            
            # Convert to more readable units
            units = ['seconds', 'minutes', 'hours', 'days', 'years']
            time_values = [
                classical_time_seconds,
                classical_time_seconds / 60,
                classical_time_seconds / 3600,
                classical_time_seconds / 86400,
                classical_time_seconds / 31536000
            ]
            
            # Find appropriate time unit for classical time
            classical_unit_idx = 0
            for i, v in enumerate(time_values):
                if v < 1e10:
                    classical_unit_idx = i
                    break
            classical_time_unit = units[min(4, classical_unit_idx)]
            classical_time_value = time_values[min(4, classical_unit_idx)]
            
            # Find appropriate time unit for quantum time
            quantum_time_values = [
                quantum_time_seconds,
                quantum_time_seconds / 60,
                quantum_time_seconds / 3600,
                quantum_time_seconds / 86400,
                quantum_time_seconds / 31536000
            ]
            
            quantum_unit_idx = 0
            for i, v in enumerate(quantum_time_values):
                if v < 1e10:
                    quantum_unit_idx = i
                    break
            quantum_time_unit = units[min(4, quantum_unit_idx)]
            quantum_time_value = quantum_time_values[min(4, quantum_unit_idx)]
            
        except Exception as e:
            print(f"Error in quantum simulation calculation: {str(e)}")
            # Provide default values in case of calculation error
            classical_search_space = float('inf')
            quantum_search_space = float('inf')
            classical_time_value = float('inf')
            classical_time_unit = 'years'
            quantum_time_value = float('inf')
            quantum_time_unit = 'years'
        
        result = {
            'attack_type': 'quantum_grover',
            'classical_search_space': classical_search_space,
            'quantum_search_space': quantum_search_space,
            'classical_time_value': classical_time_value,
            'classical_time_unit': classical_time_unit,
            'quantum_time_value': quantum_time_value,
            'quantum_time_unit': quantum_time_unit,
            'speedup_factor': quantum_speedup_factor,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results.append(result)
        return result
    
    def plot_attack_results(self, filename: Optional[str] = None) -> None:
        """
        Plot the results of the simulations
        
        Args:
            filename: Optional file to save the plot to
        """
        if not self.results:
            print("No simulation results to plot")
            return
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Group results by attack type
        attack_types = set(r['attack_type'] for r in self.results)
        
        for attack_type in attack_types:
            type_results = [r for r in self.results if r['attack_type'] == attack_type]
            
            if attack_type in ['random', 'position_known']:
                attempts = [r.get('attempts', 0) for r in type_results]
                closest = [r.get('closest_distance', float('inf')) for r in type_results]
                times = [r.get('elapsed_time', 0) for r in type_results]
                
                ax.scatter(attempts, closest, label=f"{attack_type} attack")
        
        ax.set_xscale('log')
        ax.set_yscale('log')
        ax.set_xlabel('Number of Attempts')
        ax.set_ylabel('Closest Distance to Actual Key')
        ax.set_title('Attack Simulation Results')
        ax.legend()
        ax.grid(True, which='both', linestyle='--', linewidth=0.5)
        
        if filename:
            plt.savefig(filename)
        else:
            plt.show()
    
    def save_results(self, filename: str) -> None:
        """
        Save simulation results to a file
        
        Args:
            filename: Path to save the results to
        """
        with open(filename, 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            serializable_results = []
            for result in self.results:
                result_copy = result.copy()
                for key, value in result_copy.items():
                    if isinstance(value, np.ndarray):
                        result_copy[key] = value.tolist()
                    elif isinstance(value, np.floating):
                        result_copy[key] = float(value)
                    elif isinstance(value, np.integer):
                        result_copy[key] = int(value)
                serializable_results.append(result_copy)
            
            json.dump(serializable_results, f, indent=2)
    
    @classmethod
    def load_results(cls, filename: str) -> List[Dict[str, Any]]:
        """
        Load simulation results from a file
        
        Args:
            filename: Path to the results file
            
        Returns:
            List of result dictionaries
        """
        with open(filename, 'r') as f:
            results = json.load(f)
        return results


# Add support for using as imported module or as a script
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VBSKS Security Simulator")
    parser.add_argument(
        "--db", required=True, help="Path to vector database file"
    )
    parser.add_argument(
        "--key", required=True, help="Path to key data file"
    )
    parser.add_argument(
        "--random-attempts", type=int, default=1000,
        help="Number of random brute force attempts"
    )
    parser.add_argument(
        "--position-known-attempts", type=int, default=100,
        help="Number of position-known attempts"
    )
    parser.add_argument(
        "--quantum", action="store_true",
        help="Run quantum simulation"
    )
    parser.add_argument(
        "--output", help="Path to save results"
    )
    parser.add_argument(
        "--plot", help="Path to save plot"
    )
    
    args = parser.parse_args()
    
    # Load database and key
    vector_db = VectorDatabase.load(args.db)
    key_data = KeyManager.load_key_data(args.key)
    
    key_manager = KeyManager(
        vector_db,
        key_length=key_data['key_length'],
        threshold=key_data['threshold']
    )
    
    simulator = SecuritySimulator(
        vector_db,
        key_manager,
        key_data['positions'],
        key_data['key_vectors']
    )
    
    # Run simulations
    if args.random_attempts > 0:
        print(f"Running random attack simulation with {args.random_attempts} attempts...")
        simulator.random_attack(args.random_attempts)
    
    if args.position_known_attempts > 0:
        print(f"Running position-known attack with {args.position_known_attempts} attempts...")
        simulator.position_known_attack(args.position_known_attempts)
    
    if args.quantum:
        print("Running quantum attack simulation...")
        simulator.quantum_grover_simulation()
    
    # Save results
    if args.output:
        print(f"Saving results to {args.output}")
        simulator.save_results(args.output)
    
    # Plot results
    if args.plot:
        print(f"Saving plot to {args.plot}")
        simulator.plot_attack_results(args.plot)
    else:
        simulator.plot_attack_results() 