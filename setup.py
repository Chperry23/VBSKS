#!/usr/bin/env python3
"""
Vector-Based Secure Key Storage (VBSKS) - Quantum-Resistant Key Storage
"""

import os
from setuptools import setup, find_packages

VERSION = '1.0.0'
DESCRIPTION = 'Vector-Based Secure Key Storage (VBSKS)'
LONG_DESCRIPTION = """
# Vector-Based Secure Key Storage (VBSKS)

A quantum-resistant key storage system that leverages a noise-filled, 
high-dimensional vector space to securely store cryptographic keys or passwords.

## Features

- High-dimensional, high-precision noise database
- Secure embedding of key vectors within the noise
- Retrieval mechanism with precise Euclidean distance validation
- Brute-force and quantum attack simulation
- Scalable vector space using optimized indexing
- Post-quantum cryptographic protection
- Shamir's Secret Sharing for splitting keys into multiple parts
- Multiple layers of encryption including password protection
- Database obfuscation to hide statistical patterns
- Dynamic key reconfiguration

For more information, visit https://github.com/vbsks/vbsks
"""

# Base dependencies 
REQUIRES = [
    'numpy>=1.24.0,<2.0.0',
    'scipy>=1.10.0,<2.0.0',
    'cryptography>=40.0.0,<41.0.0',
    'pydantic>=1.10.0,<2.0.0',
    'flask>=2.3.0,<3.0.0',
    'flask-cors>=4.0.0,<5.0.0',
    'tqdm>=4.65.0,<5.0.0',
    'python-dotenv>=1.0.0,<2.0.0',
]

# Optional dependencies
EXTRAS_REQUIRE = {
    'api': [
        'flask>=2.3.0,<3.0.0',
        'flask-cors>=4.0.0,<5.0.0',
    ],
    'indexing': [
        'faiss-cpu>=1.7.0,<2.0.0',
    ],
    'dev': [
        'pytest>=7.3.0,<8.0.0',
        'black>=23.3.0,<24.0.0',
        'mypy>=1.3.0,<2.0.0',
    ],
}

# Determine which files to include
def package_files(directory):
    paths = []
    for (path, _, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.py'):
                paths.append(os.path.join('..', path, filename))
    return paths

# Setup metadata
setup(
    name='vbsks',
    version=VERSION,
    author="VBSKS Development Team",
    author_email="info@vbsks.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/vbsks/vbsks",
    packages=find_packages(),
    install_requires=REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'vbsks=vbsks_cli:main',
            'vbsks-api=vbsks_api:main',
        ],
    },
    package_data={
        '': ['*.md'],
    },
) 