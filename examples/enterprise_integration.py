#!/usr/bin/env python3
"""
Enterprise Integration Example

This example demonstrates how to use the VBSKS REST API for enterprise integrations.
"""

import os
import sys
import json
import base64
import argparse
import requests
from uuid import uuid4

def setup_argparse():
    """Set up command-line arguments"""
    parser = argparse.ArgumentParser(
        description="VBSKS Enterprise Integration Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start API server first: python vbsks_api.py
  
  # Check API status
  python enterprise_integration.py status
  
  # Store a key
  python enterprise_integration.py store --key-id api_key_1 --password secure-password
  
  # List all keys
  python enterprise_integration.py list
  
  # Retrieve a key
  python enterprise_integration.py retrieve --key-id api_key_1 --password secure-password
  
  # Delete a key
  python enterprise_integration.py delete --key-id api_key_1
"""
    )
    
    # Add subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Status command
    subparsers.add_parser("status", help="Check API status")
    
    # Store command
    store_parser = subparsers.add_parser("store", help="Store a key")
    store_parser.add_argument("--key-id", required=True, help="Key identifier")
    store_parser.add_argument("--password", required=True, help="Password for encryption")
    store_parser.add_argument("--data", help="Data to store (if not provided, random will be generated)")
    store_parser.add_argument("--metadata", help="JSON metadata string")
    
    # List command
    subparsers.add_parser("list", help="List all keys")
    
    # Retrieve command
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve a key")
    retrieve_parser.add_argument("--key-id", required=True, help="Key identifier")
    retrieve_parser.add_argument("--password", required=True, help="Password for decryption")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a key")
    delete_parser.add_argument("--key-id", required=True, help="Key identifier")
    
    # Global arguments
    parser.add_argument("--api-url", default="http://localhost:5000", help="API server URL")
    parser.add_argument("--api-key", help="API key for authentication")
    
    return parser

class EnterpriseVBSKSClient:
    """Client for interacting with VBSKS API"""
    
    def __init__(self, api_url, api_key=None):
        """Initialize with API URL and optional API key"""
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key or os.environ.get("VBSKS_API_KEY")
        
        # If no API key is provided, check if there's a file with the key
        if not self.api_key:
            api_key_file = os.path.join(os.path.dirname(__file__), "api_key.txt")
            if os.path.exists(api_key_file):
                with open(api_key_file, 'r') as f:
                    self.api_key = f.read().strip()
        
        # Headers for API requests
        self.headers = {'Content-Type': 'application/json'}
        if self.api_key:
            self.headers['X-API-Key'] = self.api_key
    
    def check_status(self):
        """Check API status"""
        url = f"{self.api_url}/api/status"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def list_keys(self):
        """List all keys"""
        url = f"{self.api_url}/api/keys"
        response = requests.get(url, headers=self.headers)
        if response.status_code != 200:
            return {"status": "error", "error": f"HTTP {response.status_code}: {response.text}"}
        return response.json()
    
    def store_key(self, key_id, password, data=None, metadata=None):
        """Store a key"""
        url = f"{self.api_url}/api/keys"
        
        # If no data provided, generate random data
        if data is None:
            data = str(uuid4())
        
        # Prepare request body
        request_data = {
            "key_id": key_id,
            "master_password": password,
            "key_data": data,
            "metadata": metadata or {}
        }
        
        response = requests.post(url, headers=self.headers, json=request_data)
        if response.status_code not in [200, 201]:
            return {"status": "error", "error": f"HTTP {response.status_code}: {response.text}"}
        return response.json()
    
    def retrieve_key(self, key_id, password):
        """Retrieve a key"""
        url = f"{self.api_url}/api/keys/{key_id}/retrieve"
        
        request_data = {
            "master_password": password
        }
        
        response = requests.post(url, headers=self.headers, json=request_data)
        if response.status_code != 200:
            return {"status": "error", "error": f"HTTP {response.status_code}: {response.text}"}
        return response.json()
    
    def delete_key(self, key_id):
        """Delete a key"""
        url = f"{self.api_url}/api/keys/{key_id}"
        
        response = requests.delete(url, headers=self.headers)
        if response.status_code != 200:
            return {"status": "error", "error": f"HTTP {response.status_code}: {response.text}"}
        return response.json()

def format_result(result):
    """Format API result for display"""
    return json.dumps(result, indent=2)

def main():
    """Main function"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize client
    client = EnterpriseVBSKSClient(args.api_url, args.api_key)
    
    # Execute command
    if args.command == "status":
        print("Checking API status...")
        result = client.check_status()
        print(format_result(result))
    
    elif args.command == "list":
        print("Listing keys...")
        result = client.list_keys()
        print(format_result(result))
    
    elif args.command == "store":
        print(f"Storing key '{args.key_id}'...")
        
        # Parse metadata if provided
        metadata = None
        if args.metadata:
            try:
                metadata = json.loads(args.metadata)
            except json.JSONDecodeError:
                print("Error: Invalid JSON metadata")
                return
        
        result = client.store_key(args.key_id, args.password, args.data, metadata)
        print(format_result(result))
    
    elif args.command == "retrieve":
        print(f"Retrieving key '{args.key_id}'...")
        result = client.retrieve_key(args.key_id, args.password)
        
        if result.get("status") == "success":
            # Display the key in a more readable format
            crypto_key = result.get("crypto_key")
            if crypto_key:
                try:
                    key_bytes = base64.b64decode(crypto_key)
                    key_text = key_bytes.decode('utf-8')
                    result["decoded_key"] = key_text
                except:
                    pass
        
        print(format_result(result))
    
    elif args.command == "delete":
        print(f"Deleting key '{args.key_id}'...")
        result = client.delete_key(args.key_id)
        print(format_result(result))

if __name__ == "__main__":
    main() 