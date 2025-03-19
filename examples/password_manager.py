#!/usr/bin/env python3
"""
VBSKS Password Manager Example

This script demonstrates how to use VBSKS to build a simple password manager.
It provides a command-line interface for storing, retrieving, and managing passwords.
"""

import os
import sys
import argparse
import getpass
import json
import random
import string
import base64
from pathlib import Path

# Add parent directory to path for imports when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from vbsks_easy import VBSKSEasy
except ImportError:
    print("Error: vbsks_easy module not found. Make sure VBSKS is installed or in your Python path.")
    sys.exit(1)

# Configuration
DEFAULT_DB_FOLDER = os.path.expanduser("~/.vbsks_passwords")
CONFIG_FILE = os.path.join(DEFAULT_DB_FOLDER, "config.json")

class PasswordManager:
    """Simple password manager using VBSKS for secure storage."""
    
    def __init__(self, db_folder=DEFAULT_DB_FOLDER):
        """Initialize the password manager."""
        self.db_folder = Path(db_folder)
        self.db_folder.mkdir(parents=True, exist_ok=True)
        
        # Load or create configuration
        self.config = self._load_config()
        
        # Initialize VBSKS
        self.vbsks = VBSKSEasy(
            db_folder=self.db_folder,
            auto_reconfigure=self.config.get("auto_reconfigure", True),
            reconfiguration_interval=self.config.get("reconfiguration_interval", 86400),
            dimensions=self.config.get("dimensions", 100),
            db_size=self.config.get("db_size", 10000),
            key_length=self.config.get("key_length", 8)
        )
    
    def _load_config(self):
        """Load or create configuration file."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Error loading config file: {str(e)}")
        
        # Default configuration
        config = {
            "auto_reconfigure": True,
            "reconfiguration_interval": 86400,  # 24 hours
            "dimensions": 100,
            "db_size": 10000,
            "key_length": 8,
            "password_generator": {
                "length": 16,
                "use_symbols": True,
                "use_numbers": True,
                "use_uppercase": True,
                "use_lowercase": True
            }
        }
        
        # Save default configuration
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Warning: Error saving config file: {str(e)}")
        
        return config
    
    def add_password(self, site, username, password=None, notes=None):
        """Add or update a password."""
        # Generate a password if not provided
        if not password:
            password = self._generate_password()
            print(f"Generated password: {password}")
        
        # Create key_id from site and username
        key_id = f"{site}_{username}".lower().replace(" ", "_")
        
        # Create metadata
        metadata = {
            "site": site,
            "username": username,
            "notes": notes
        }
        
        # Get master password
        master_password = self._get_master_password()
        
        # Store the password
        result = self.vbsks.store_key(
            key_id=key_id,
            master_password=master_password,
            data=password,
            metadata=metadata
        )
        
        if result['status'] == 'success':
            print(f"\nPassword for {site} (username: {username}) stored successfully.")
            return True
        else:
            print(f"\nError storing password: {result.get('error', 'Unknown error')}")
            return False
    
    def get_password(self, site, username):
        """Retrieve a password."""
        # Create key_id from site and username
        key_id = f"{site}_{username}".lower().replace(" ", "_")
        
        # Get master password
        master_password = self._get_master_password()
        
        # Retrieve the password
        result = self.vbsks.retrieve_key(
            key_id=key_id,
            master_password=master_password
        )
        
        if result['status'] == 'success':
            # Decode the key
            crypto_key = result['crypto_key']
            password_bytes = base64.b64decode(crypto_key)
            
            try:
                # Try to interpret as UTF-8 string
                password = password_bytes.decode('utf-8')
                
                if result.get('reconfigured'):
                    print("\nNote: Password was automatically reconfigured for enhanced security.")
                
                return password
            except UnicodeDecodeError:
                # If it's not a valid UTF-8 string, return hex representation
                return password_bytes.hex()
        else:
            print(f"\nError retrieving password: {result.get('error', 'Unknown error')}")
            return None
    
    def list_passwords(self):
        """List all stored passwords."""
        # Get all keys
        result = self.vbsks.list_keys()
        
        if result['status'] == 'success':
            keys = result['keys']
            
            if not keys:
                print("No passwords stored yet.")
                return []
            
            passwords = []
            for key_id, info in keys.items():
                metadata = info.get('metadata', {})
                if 'site' in metadata and 'username' in metadata:
                    passwords.append({
                        'site': metadata['site'],
                        'username': metadata['username'],
                        'key_id': key_id,
                        'created': info.get('created'),
                        'notes': metadata.get('notes')
                    })
            
            return passwords
        else:
            print(f"\nError listing passwords: {result.get('error', 'Unknown error')}")
            return []
    
    def delete_password(self, site, username):
        """Delete a password."""
        # Create key_id from site and username
        key_id = f"{site}_{username}".lower().replace(" ", "_")
        
        # Delete the password
        result = self.vbsks.delete_key(key_id)
        
        if result['status'] == 'success':
            print(f"\nPassword for {site} (username: {username}) deleted successfully.")
            return True
        else:
            print(f"\nError deleting password: {result.get('error', 'Unknown error')}")
            return False
    
    def create_backup(self):
        """Create a backup of the password database."""
        # Get backup password
        print("\nCreating backup of your password database.")
        print("Please choose a strong backup password (different from your master password).")
        backup_password = getpass.getpass("Backup password: ")
        backup_password_confirm = getpass.getpass("Confirm backup password: ")
        
        if backup_password != backup_password_confirm:
            print("Error: Passwords do not match.")
            return False
        
        # Create the backup
        result = self.vbsks.backup_database(backup_password)
        
        if result['status'] == 'success':
            print("\nBackup created successfully:")
            print(f"Backup file: {result['backup_file']}")
            print(f"Key map backup: {result['key_map_backup']}")
            print("\nSTORE THESE FILES SECURELY - THEY CONTAIN YOUR PASSWORDS!")
            return True
        else:
            print(f"\nError creating backup: {result.get('error', 'Unknown error')}")
            return False
    
    def restore_backup(self, backup_file, key_map_backup=None):
        """Restore a backup of the password database."""
        if not os.path.exists(backup_file):
            print(f"Error: Backup file not found: {backup_file}")
            return False
        
        if key_map_backup and not os.path.exists(key_map_backup):
            print(f"Error: Key map backup file not found: {key_map_backup}")
            return False
        
        # Get backup password
        print("\nRestoring backup of your password database.")
        backup_password = getpass.getpass("Backup password: ")
        
        # Confirm restoration
        confirm = input("This will overwrite your current password database. Continue? (y/N): ")
        if confirm.lower() != 'y':
            print("Restoration cancelled.")
            return False
        
        # Restore the backup
        result = self.vbsks.restore_database(
            backup_file=backup_file,
            backup_password=backup_password,
            key_map_backup=key_map_backup
        )
        
        if result['status'] == 'success':
            print("\nBackup restored successfully.")
            print(f"Loaded {result['size']} vectors with {result['dimensions']} dimensions.")
            
            if result['key_map_restored']:
                print("Key map restored successfully.")
            else:
                print("Warning: Key map was not restored. Some password metadata may be missing.")
            
            return True
        else:
            print(f"\nError restoring backup: {result.get('error', 'Unknown error')}")
            return False
    
    def _generate_password(self):
        """Generate a secure random password."""
        config = self.config.get("password_generator", {})
        
        length = config.get("length", 16)
        use_symbols = config.get("use_symbols", True)
        use_numbers = config.get("use_numbers", True)
        use_uppercase = config.get("use_uppercase", True)
        use_lowercase = config.get("use_lowercase", True)
        
        # Ensure at least one character type is selected
        if not any([use_symbols, use_numbers, use_uppercase, use_lowercase]):
            use_lowercase = True
        
        # Define character sets
        chars = []
        if use_lowercase:
            chars.extend(string.ascii_lowercase)
        if use_uppercase:
            chars.extend(string.ascii_uppercase)
        if use_numbers:
            chars.extend(string.digits)
        if use_symbols:
            chars.extend("!@#$%^&*()_+-=[]{}|;:,.<>?")
        
        # Generate password
        secure_random = random.SystemRandom()
        password = ''.join(secure_random.choice(chars) for _ in range(length))
        
        return password
    
    def _get_master_password(self):
        """Get the master password from the user."""
        return getpass.getpass("Enter master password: ")

def setup_argparse():
    """Set up command-line argument parsing."""
    parser = argparse.ArgumentParser(
        description="VBSKS Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add a new password
  python password_manager.py add --site example.com --username user@example.com
  
  # Generate a password
  python password_manager.py add --site example.com --username user@example.com --generate
  
  # Get a password
  python password_manager.py get --site example.com --username user@example.com
  
  # List all passwords
  python password_manager.py list
  
  # Delete a password
  python password_manager.py delete --site example.com --username user@example.com
  
  # Create a backup
  python password_manager.py backup
  
  # Restore from backup
  python password_manager.py restore --backup-file ~/.vbsks_passwords/backups/vbsks_backup_1234567890.json
"""
    )
    
    # Add subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add or update a password")
    add_parser.add_argument("--site", required=True, help="Website or application name")
    add_parser.add_argument("--username", required=True, help="Username for the site")
    add_parser.add_argument("--password", help="Password to store (will be prompted if not provided)")
    add_parser.add_argument("--generate", action="store_true", help="Generate a secure random password")
    add_parser.add_argument("--notes", help="Additional notes about this password")
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Retrieve a password")
    get_parser.add_argument("--site", required=True, help="Website or application name")
    get_parser.add_argument("--username", required=True, help="Username for the site")
    
    # List command
    subparsers.add_parser("list", help="List all stored passwords")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a password")
    delete_parser.add_argument("--site", required=True, help="Website or application name")
    delete_parser.add_argument("--username", required=True, help="Username for the site")
    
    # Backup command
    subparsers.add_parser("backup", help="Create a backup of the password database")
    
    # Restore command
    restore_parser = subparsers.add_parser("restore", help="Restore from a backup")
    restore_parser.add_argument("--backup-file", required=True, help="Path to the backup file")
    restore_parser.add_argument("--key-map-backup", help="Path to the key map backup file (optional)")
    
    # Global options
    parser.add_argument("--db-folder", help="Database folder path", default=DEFAULT_DB_FOLDER)
    
    return parser

def main():
    """Main function."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize password manager
    manager = PasswordManager(db_folder=args.db_folder)
    
    # Execute the command
    if args.command == "add":
        password = None
        if args.generate:
            # Generate a password
            password = manager._generate_password()
        elif args.password:
            # Use provided password
            password = args.password
        else:
            # Prompt for password
            password = getpass.getpass("Enter password to store: ")
            password_confirm = getpass.getpass("Confirm password: ")
            
            if password != password_confirm:
                print("Error: Passwords do not match.")
                return
        
        manager.add_password(args.site, args.username, password, args.notes)
    
    elif args.command == "get":
        password = manager.get_password(args.site, args.username)
        if password:
            print(f"\nPassword for {args.site} (username: {args.username}):")
            print(password)
    
    elif args.command == "list":
        passwords = manager.list_passwords()
        if passwords:
            print(f"\nStored passwords ({len(passwords)}):")
            for idx, pwd in enumerate(passwords, 1):
                print(f"\n{idx}. Site: {pwd['site']}")
                print(f"   Username: {pwd['username']}")
                if pwd.get('notes'):
                    print(f"   Notes: {pwd['notes']}")
    
    elif args.command == "delete":
        manager.delete_password(args.site, args.username)
    
    elif args.command == "backup":
        manager.create_backup()
    
    elif args.command == "restore":
        manager.restore_backup(args.backup_file, args.key_map_backup)

if __name__ == "__main__":
    main() 