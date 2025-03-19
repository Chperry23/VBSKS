#!/usr/bin/env python3
"""
VBSKS CLI - Simple command-line interface for Vector-Based Secure Key Storage

This script provides an easy-to-use CLI for managing keys with VBSKS.
"""

import os
import sys
import argparse
import getpass
import json
import base64
from pathlib import Path

from vbsks_easy import VBSKSEasy

def setup_argparse():
    """Set up command-line argument parsing"""
    parser = argparse.ArgumentParser(
        description="VBSKS - Vector-Based Secure Key Storage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize a new VBSKS database
  vbsks_cli.py init --db-folder ~/vbsks_keys
  
  # Store a new key
  vbsks_cli.py store --key-id my_server_key --db-folder ~/vbsks_keys
  
  # Retrieve a key
  vbsks_cli.py retrieve --key-id my_server_key --db-folder ~/vbsks_keys
  
  # List all keys
  vbsks_cli.py list --db-folder ~/vbsks_keys
  
  # Delete a key
  vbsks_cli.py delete --key-id my_server_key --db-folder ~/vbsks_keys
  
  # Create a backup
  vbsks_cli.py backup --db-folder ~/vbsks_keys
  
  # Restore from backup
  vbsks_cli.py restore --backup-file ~/vbsks_keys/backups/vbsks_backup_1234567890.json --db-folder ~/vbsks_keys
"""
    )
    
    # Add subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # init command
    init_parser = subparsers.add_parser("init", help="Initialize a new VBSKS database")
    init_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    init_parser.add_argument("--dimensions", type=int, help="Vector dimensions", default=100)
    init_parser.add_argument("--db-size", type=int, help="Database size", default=10000)
    init_parser.add_argument("--key-length", type=int, help="Key length (vectors)", default=8)
    init_parser.add_argument("--no-reconfigure", action="store_true", help="Disable automatic reconfiguration")
    
    # store command
    store_parser = subparsers.add_parser("store", help="Store a key in the database")
    store_parser.add_argument("--key-id", required=True, help="Unique identifier for the key")
    store_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    store_parser.add_argument("--key-data", help="Data to use as key (optional)")
    store_parser.add_argument("--key-file", help="File with data to use as key (optional)")
    store_parser.add_argument("--metadata", help="JSON metadata to associate with the key")
    
    # retrieve command
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve a key from the database")
    retrieve_parser.add_argument("--key-id", required=True, help="Key identifier to retrieve")
    retrieve_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    retrieve_parser.add_argument("--output", help="Output file to save the key (optional)")
    retrieve_parser.add_argument("--raw", action="store_true", help="Output raw key data instead of Base64")
    
    # list command
    list_parser = subparsers.add_parser("list", help="List all keys in the database")
    list_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    list_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    # delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a key from the database")
    delete_parser.add_argument("--key-id", required=True, help="Key identifier to delete")
    delete_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    delete_parser.add_argument("--force", action="store_true", help="Don't ask for confirmation")
    
    # backup command
    backup_parser = subparsers.add_parser("backup", help="Create a secure backup of the database")
    backup_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    backup_parser.add_argument("--output", help="Output folder for backup files")
    
    # restore command
    restore_parser = subparsers.add_parser("restore", help="Restore database from a backup")
    restore_parser.add_argument("--backup-file", required=True, help="Backup file to restore from")
    restore_parser.add_argument("--key-map-backup", help="Key map backup file (optional)")
    restore_parser.add_argument("--db-folder", help="Database folder path", default="vbsks_data")
    
    return parser

def init_command(args):
    """Initialize a new VBSKS database"""
    # Check if database already exists
    db_path = Path(args.db_folder) / "vbsks_db.json"
    if db_path.exists():
        overwrite = input(f"Database already exists at {db_path}. Overwrite? (y/N): ")
        if overwrite.lower() != 'y':
            print("Operation cancelled.")
            return
    
    # Initialize VBSKSEasy with user parameters
    vbsks = VBSKSEasy(
        db_folder=args.db_folder,
        auto_reconfigure=not args.no_reconfigure,
        dimensions=args.dimensions,
        db_size=args.db_size,
        key_length=args.key_length
    )
    
    print(f"VBSKS database initialized successfully at {args.db_folder}")
    print(f"Vector dimensions: {args.dimensions}")
    print(f"Database size: {args.db_size}")
    print(f"Key length: {args.key_length}")
    print(f"Auto reconfiguration: {'Disabled' if args.no_reconfigure else 'Enabled'}")

def store_command(args):
    """Store a key in the database"""
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Get key data if provided
    key_data = None
    if args.key_data:
        key_data = args.key_data
    elif args.key_file:
        if not os.path.exists(args.key_file):
            print(f"Error: Key file not found: {args.key_file}")
            return
        with open(args.key_file, 'rb') as f:
            key_data = f.read()
    
    # Get metadata if provided
    metadata = {}
    if args.metadata:
        try:
            metadata = json.loads(args.metadata)
        except json.JSONDecodeError:
            print("Error: Invalid JSON metadata")
            return
    
    # Get master password
    master_password = getpass.getpass("Enter master password: ")
    
    # Store the key
    result = vbsks.store_key(
        key_id=args.key_id,
        master_password=master_password,
        data=key_data,
        metadata=metadata
    )
    
    if result['status'] == 'success':
        print(f"Key '{args.key_id}' stored successfully")
        print(f"Key file: {result['key_file']}")
    else:
        print(f"Error storing key: {result.get('error', 'Unknown error')}")

def retrieve_command(args):
    """Retrieve a key from the database"""
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Get master password
    master_password = getpass.getpass("Enter master password: ")
    
    # Retrieve the key
    result = vbsks.retrieve_key(
        key_id=args.key_id,
        master_password=master_password
    )
    
    if result['status'] == 'success':
        print(f"Key '{args.key_id}' retrieved successfully")
        
        if result.get('reconfigured'):
            print("Note: Key was automatically reconfigured for enhanced security")
        
        # Display or save the key
        crypto_key = result['crypto_key']
        if args.raw:
            crypto_key_bytes = base64.b64decode(crypto_key)
            
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(crypto_key_bytes)
                print(f"Raw key saved to {args.output}")
            else:
                # Display hex representation
                print("Key (hex):", crypto_key_bytes.hex())
        else:
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(crypto_key)
                print(f"Base64 key saved to {args.output}")
            else:
                print("Key (base64):", crypto_key)
    else:
        print(f"Error retrieving key: {result.get('error', 'Unknown error')}")

def list_command(args):
    """List all keys in the database"""
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Get keys
    result = vbsks.list_keys()
    
    if result['status'] == 'success':
        keys = result['keys']
        
        if args.json:
            print(json.dumps(keys, indent=2))
        else:
            if not keys:
                print("No keys found.")
                return
            
            print(f"Found {len(keys)} keys:")
            for key_id, info in keys.items():
                created = info.get('created')
                last_reconfigured = info.get('last_reconfigured')
                
                print(f"\nKey ID: {key_id}")
                print(f"  Created: {time_to_str(created) if created else 'Unknown'}")
                print(f"  Last reconfigured: {time_to_str(last_reconfigured) if last_reconfigured else 'Never'}")
                
                # Print metadata if available
                metadata = info.get('metadata', {})
                if metadata:
                    print("  Metadata:")
                    for k, v in metadata.items():
                        if k != 'key_id' and k != 'timestamp':
                            print(f"    {k}: {v}")
    else:
        print(f"Error listing keys: {result.get('error', 'Unknown error')}")

def delete_command(args):
    """Delete a key from the database"""
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Check if the key exists
    result = vbsks.list_keys()
    if result['status'] == 'success':
        keys = result['keys']
        if args.key_id not in keys:
            print(f"Error: Key '{args.key_id}' not found")
            return
    
    # Confirm deletion unless --force is used
    if not args.force:
        confirm = input(f"Delete key '{args.key_id}'? This action cannot be undone. (y/N): ")
        if confirm.lower() != 'y':
            print("Operation cancelled.")
            return
    
    # Delete the key
    result = vbsks.delete_key(args.key_id)
    
    if result['status'] == 'success':
        print(f"Key '{args.key_id}' deleted successfully")
    else:
        print(f"Error deleting key: {result.get('error', 'Unknown error')}")

def backup_command(args):
    """Create a secure backup of the database"""
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Get backup password
    backup_password = getpass.getpass("Enter backup password: ")
    backup_password_confirm = getpass.getpass("Confirm backup password: ")
    
    if backup_password != backup_password_confirm:
        print("Error: Passwords do not match")
        return
    
    # Create backup
    result = vbsks.backup_database(backup_password)
    
    if result['status'] == 'success':
        print(f"Database backup created successfully")
        print(f"Backup file: {result['backup_file']}")
        print(f"Key map backup: {result['key_map_backup']}")
    else:
        print(f"Error creating backup: {result.get('error', 'Unknown error')}")

def restore_command(args):
    """Restore database from a backup"""
    # Check if backup file exists
    if not os.path.exists(args.backup_file):
        print(f"Error: Backup file not found: {args.backup_file}")
        return
    
    # Check if key map backup exists if provided
    if args.key_map_backup and not os.path.exists(args.key_map_backup):
        print(f"Error: Key map backup file not found: {args.key_map_backup}")
        return
    
    # Initialize VBSKS
    vbsks = VBSKSEasy(db_folder=args.db_folder)
    
    # Get backup password
    backup_password = getpass.getpass("Enter backup password: ")
    
    # Confirm restoration
    confirm = input(f"Restore database from backup? This will overwrite the current database. (y/N): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        return
    
    # Restore database
    result = vbsks.restore_database(
        backup_file=args.backup_file,
        backup_password=backup_password,
        key_map_backup=args.key_map_backup
    )
    
    if result['status'] == 'success':
        print(f"Database restored successfully")
        print(f"Dimensions: {result['dimensions']}")
        print(f"Size: {result['size']}")
        
        if result['key_map_restored']:
            print("Key map restored successfully")
    else:
        print(f"Error restoring database: {result.get('error', 'Unknown error')}")

def time_to_str(timestamp):
    """Convert a timestamp to a readable string"""
    if not timestamp:
        return "Unknown"
    
    import datetime
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def main():
    """Main function"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute the command
    if args.command == "init":
        init_command(args)
    elif args.command == "store":
        store_command(args)
    elif args.command == "retrieve":
        retrieve_command(args)
    elif args.command == "list":
        list_command(args)
    elif args.command == "delete":
        delete_command(args)
    elif args.command == "backup":
        backup_command(args)
    elif args.command == "restore":
        restore_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 