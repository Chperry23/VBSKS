# VBSKS Examples

This directory contains example applications and scripts that demonstrate various features and use cases for Vector-Based Secure Key Storage (VBSKS).

## Example Overview

| Example | Description | Ideal For |
|---------|-------------|-----------|
| [Basic Key Management](#basic-key-management) | Simple key storage and retrieval | Getting started |
| [Dynamic Reconfiguration](#dynamic-reconfiguration) | Demonstrates key vector reconfiguration | Understanding security features |
| [Enterprise Integration](#enterprise-integration) | Using VBSKS with the REST API | Enterprise developers |
| [High Security Setup](#high-security-setup) | Maximum security configuration | Government & high-security applications |
| [Password Manager](#password-manager) | Full password manager built with VBSKS | Consumer applications |

## Requirements

All examples require the VBSKS core modules to be accessible. For development, you can run the examples from the repository root to ensure proper imports. In a production environment, examples should be run after installing the VBSKS package.

```bash
# Run from the repository root
cd /path/to/vbsks
python examples/basic_key_management.py

# Or if VBSKS is installed
python basic_key_management.py
```

## Basic Key Management

**File:** `basic_key_management.py`

This example demonstrates the fundamental operations of VBSKS:

- Initializing a vector database
- Storing a key with metadata
- Listing stored keys
- Retrieving a key
- Creating database backups
- Deleting keys

It's ideal for getting started with VBSKS and understanding the basic workflow.

```bash
python examples/basic_key_management.py
```

## Dynamic Reconfiguration

**File:** `reconfiguration_demo.py`

This example shows how VBSKS enhances security through dynamic key reconfiguration:

- Setting up automatic reconfiguration
- Monitoring position changes after reconfiguration
- Manually triggering reconfiguration
- Verifying key retrieval after reconfiguration

The reconfiguration feature is a core security component that periodically moves key vectors to new positions within the vector database, preventing long-term statistical analysis.

```bash
python examples/reconfiguration_demo.py
```

## Enterprise Integration

**File:** `enterprise_integration.py`

This example demonstrates how to integrate VBSKS into enterprise systems using the REST API:

- API client implementation
- Authentication with API keys
- Storing and retrieving keys via API calls
- Error handling and response parsing

This is particularly useful for developers integrating VBSKS into larger systems or microservices architectures.

```bash
# Start the API server first
python vbsks_api.py

# In another terminal
python examples/enterprise_integration.py status
python examples/enterprise_integration.py store --key-id test_key --password secure-pass
```

## High Security Setup

**File:** `high_security_setup.py`

This example shows how to configure VBSKS for maximum security, suitable for government agencies and high-security applications:

- High-dimensional vector spaces (256D)
- Longer key vectors (12 vectors per key)
- Tighter thresholds for comparison
- Shamir's Secret Sharing with multiple shares
- High iteration counts for password-based key derivation
- Multiple backup mechanisms
- Statistical noise addition

```bash
python examples/high_security_setup.py
```

## Password Manager

**File:** `password_manager.py`

A complete password manager application built with VBSKS:

- Secure storage of website credentials
- Password generation
- Command-line interface
- Backup and restore functionality

This example demonstrates how VBSKS can be used to build practical, consumer-facing applications.

```bash
# Initialize
python examples/password_manager.py init

# Add a password
python examples/password_manager.py add --site example.com --username user@example.com --generate

# Retrieve a password
python examples/password_manager.py get --site example.com --username user@example.com
```

## Additional Resources

These examples are meant to demonstrate basic functionality. For production use, consult the main VBSKS documentation:

- [Core Documentation](../README.md)
- [Security Guide](../docs/SECURITY.md)
- [API Reference](../docs/API.md)
- [Deployment Guide](../docs/DEPLOYMENT.md)

## Security Note

Some examples use simplified settings or fixed passwords for demonstration purposes. In production environments, always:

1. Use strong, unique passwords
2. Store sensitive data securely
3. Configure appropriate security parameters
4. Implement proper access controls
5. Follow security best practices for your specific environment 