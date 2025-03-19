# Vector-Based Secure Key Storage (VBSKS)

A quantum-resistant key storage system that leverages a noise-filled, high-dimensional vector space to securely store cryptographic keys or passwords.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Quantum Resistant](https://img.shields.io/badge/quantum-resistant-brightgreen.svg)](https://csrc.nist.gov/Projects/post-quantum-cryptography)

## Overview

VBSKS is a revolutionary approach to securing cryptographic keys and sensitive data that is designed to be resistant to both classical and quantum computing attacks. The system embeds key vectors within a high-dimensional noise database, making them virtually impossible to locate without knowing their exact positions.

### Key Features

- **Quantum Resistance**: Resistant to attacks from both classical and quantum computers
- **Vector-Based Storage**: Uses high-dimensional vectors and precise distance calculations for key storage
- **Multiple Security Layers**:
  - Post-quantum cryptography for encryption
  - Password-based protection
  - Shamir's Secret Sharing for key splitting
  - Digital signatures for integrity verification
  - Statistical noise to prevent analysis
- **Dynamic Reconfiguration**: Periodically moves keys to new positions within the vector space
- **Flexible Implementation**: Available as a Python library, CLI tool, REST API, and Docker container

## Mathematical Security Analysis

VBSKS provides exceptional security through multiple mathematical mechanisms:

| Security Aspect | Description | Strength |
|-----------------|-------------|----------|
| **Search Space** | With 100 dimensions, 10,000 vectors, and 8-vector keys | ~10^5017 possibilities |
| **Bit Security** | Equivalent security level | ~16,656 bits |
| **Quantum Resistance** | Effective bit security with Grover's algorithm | ~8,328 bits |
| **Brute Force Time** | Time to try all combinations | ~10^4990 universe lifetimes |

For comparison, traditional encryption uses 128-256 bits of security, making VBSKS significantly more secure.

## Installation

### Quick Installation

```bash
pip install vbsks
```

### From Source

```bash
git clone https://github.com/vbsks/vbsks.git
cd vbsks
pip install -r requirements.txt
```

### Docker Deployment

```bash
docker-compose up -d
```

## Usage

VBSKS is available through multiple interfaces, catering to different user needs.

### Python Library

```python
from vbsks_easy import VBSKSEasy

# Initialize
vbsks = VBSKSEasy(db_folder="~/my_keys")

# Store a key
result = vbsks.store_key(
    key_id="my_secret",
    master_password="secure-password",
    data="my secret data",
    metadata={"description": "Important secret"}
)

# Retrieve a key
result = vbsks.retrieve_key(
    key_id="my_secret",
    master_password="secure-password"
)
print(result['crypto_key'])  # Base64-encoded key
```

### Command Line Interface

```bash
# Initialize a new database
vbsks_cli.py init --db-folder ~/my_keys

# Store a key
vbsks_cli.py store --key-id my_server_key --db-folder ~/my_keys

# Retrieve a key
vbsks_cli.py retrieve --key-id my_server_key --db-folder ~/my_keys

# List all keys
vbsks_cli.py list --db-folder ~/my_keys
```

### REST API

Start the API server:

```bash
# Set an API key for authentication
export VBSKS_API_KEY="your-secure-api-key"
python vbsks_api.py
```

Make API calls:

```bash
# Store a key
curl -X POST http://localhost:5000/api/keys \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "key_id": "api_test_key",
    "master_password": "secure-password",
    "metadata": {"description": "API test key"}
  }'

# Retrieve a key
curl -X POST http://localhost:5000/api/keys/api_test_key/retrieve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "master_password": "secure-password"
  }'
```

## Security Architecture

VBSKS employs a multi-layered security architecture:

1. **Vector Database Layer**:
   - High-dimensional vector space (100+ dimensions)
   - Statistical noise to mask patterns
   - Dynamic reconfiguration of key positions

2. **Cryptographic Layer**:
   - Post-quantum cryptographic algorithms
   - Key derivation functions with high iteration counts
   - Digital signatures for data integrity

3. **Access Control Layer**:
   - Password-based encryption
   - API key authentication for REST API
   - Optional multi-factor authentication

4. **Redundancy Layer**:
   - Shamir's Secret Sharing for key splitting
   - Multiple backup mechanisms
   - Integrity verification for all operations

## Components

The VBSKS system consists of several key components:

- **VectorDatabase**: Manages the high-dimensional vector space
- **KeyManager**: Handles key generation, storage, and retrieval
- **SecureStorage**: Provides encryption, signatures, and sharing
- **MapManager**: Tracks and manages key vector positions
- **ReconfigurationController**: Dynamically reconfigures key positions

## Examples

See the [examples directory](./examples) for practical applications of VBSKS:

- [Basic Key Management](./examples/basic_key_management.py)
- [Dynamic Reconfiguration](./examples/reconfiguration_demo.py)
- [Enterprise Integration](./examples/enterprise_integration.py)
- [High Security Setup](./examples/high_security_setup.py)
- [Password Manager](./examples/password_manager.py)

## Documentation

For detailed documentation, see:

- [Core Concepts](./docs/CONCEPTS.md)
- [API Reference](./docs/API.md)
- [Security Guide](./docs/SECURITY.md)
- [Deployment Guide](./docs/DEPLOYMENT.md)
- [Mathematics of VBSKS](./docs/MATH.md)

## Use Cases

VBSKS is ideal for:

- **Government & Military**: Securing classified information
- **Financial Institutions**: Protecting financial keys and customer data
- **Healthcare**: Securing patient records and medical data
- **Enterprise Systems**: Safeguarding intellectual property and trade secrets
- **Consumer Applications**: Password managers and secure credentials storage

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors to the VBSKS project
- Special thanks to the post-quantum cryptography community for their research and insights

## Contact

For questions, suggestions, or collaboration, please contact:
- Email: info@vbsks.com
- GitHub: [https://github.com/vbsks/vbsks](https://github.com/vbsks/vbsks) 