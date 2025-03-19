#!/usr/bin/env python3
"""
Simple script to load and display a vector database.
This helps verify that our database loading/saving is working correctly.
"""

import os
import sys
import json
import base64
import argparse
from pathlib import Path

from vector_db import VectorDatabase
from secure_storage import SecureStorage

def display_vector_db(db, max_vectors=5):
    """Display basic information about a vector database"""
    print(f"Vector Database Information:")
    print(f"  Dimensions: {db.dimensions}")
    print(f"  Size: {db.size}")
    print(f"  Threshold: {db.threshold}")
    print(f"  Use Indexing: {db.use_indexing}")
    
    if db.size > 0:
        print(f"\nSample vectors (up to {max_vectors}):")
        for i in range(min(max_vectors, db.size)):
            vector, metadata = db.retrieve_vector(i)
            vector_preview = str(vector[:3]) + "..." if len(vector) > 3 else str(vector)
            print(f"  Vector {i}: {vector_preview}")
            if metadata:
                print(f"  Metadata: {metadata}")
            print()

def load_standard_db(filename):
    """Load a standard vector database file"""
    try:
        print(f"Loading standard database from {filename}...")
        db = VectorDatabase.load(filename)
        print("Database loaded successfully!")
        return db
    except Exception as e:
        print(f"Error loading standard database: {str(e)}")
        return None

def load_secure_db(filename, password=None):
    """Load a secure vector database file"""
    try:
        print(f"Loading secure database from {filename}...")
        secure_storage = SecureStorage()
        
        # Try loading directly
        db, info = secure_storage.secure_load_vector_db(
            filename=filename,
            encryption_password=password
        )
        
        print("Database loaded successfully!")
        print(f"Security info: {json.dumps(info, indent=2)}")
        return db
    except Exception as e:
        print(f"Error loading secure database: {str(e)}")
        
        # If direct loading failed, try recovery info
        recovery_file = filename + ".recovery_info"
        if os.path.exists(recovery_file):
            try:
                print(f"Attempting to load using recovery info: {recovery_file}")
                db, info = secure_storage.secure_load_vector_db(
                    recovery_info_file=recovery_file,
                    encryption_password=password
                )
                print("Database loaded successfully using recovery info!")
                print(f"Security info: {json.dumps(info, indent=2)}")
                return db
            except Exception as e2:
                print(f"Error loading using recovery info: {str(e2)}")
        
        return None

def main():
    parser = argparse.ArgumentParser(description="Load and display a vector database")
    parser.add_argument("filename", help="Path to the vector database file")
    parser.add_argument("--secure", action="store_true", help="Load as a secure database")
    parser.add_argument("--password", help="Password for secure database")
    args = parser.parse_args()
    
    # Check if the file exists
    if not os.path.exists(args.filename):
        print(f"Error: File not found: {args.filename}")
        return 1
    
    # Load the database
    if args.secure:
        db = load_secure_db(args.filename, args.password)
    else:
        db = load_standard_db(args.filename)
    
    # Display database info
    if db:
        display_vector_db(db)
        return 0
    else:
        print("Failed to load the database.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 