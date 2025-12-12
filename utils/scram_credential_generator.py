#!/usr/bin/env python3
"""
Copyright 2025 Aiven Oy https://aiven.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
import getpass
import hashlib
import hmac
import json
import secrets
import sys
from typing import NamedTuple


class ScramCredential(NamedTuple):
    """SCRAM credential with salt, stored_key, server_key, and iterations."""
    salt: bytes
    stored_key: bytes
    server_key: bytes
    iterations: int


def generate_scram_credential(password: str, iterations: int, hash_name: str) -> ScramCredential:
    """
    Generate SCRAM credentials for a given password.

    Args:
        password: Plain text password
        iterations: Number of PBKDF2 iterations
        hash_name: Hash algorithm name ('sha256' or 'sha512')

    Returns:
        ScramCredential with generated salt and keys
    """
    # Generate random salt (32 bytes)
    salt = secrets.token_bytes(32)

    # Compute salted password using PBKDF2
    salted_password = hashlib.pbkdf2_hmac(hash_name, password.encode('utf-8'), salt, iterations)

    # Compute client key: HMAC(salted_password, "Client Key")
    client_key = hmac.new(salted_password, b"Client Key", hash_name).digest()

    # Compute stored key: H(client_key)
    if hash_name == 'sha256':
        stored_key = hashlib.sha256(client_key).digest()
    elif hash_name == 'sha512':
        stored_key = hashlib.sha512(client_key).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_name}")

    # Compute server key: HMAC(salted_password, "Server Key")
    server_key = hmac.new(salted_password, b"Server Key", hash_name).digest()

    return ScramCredential(
        salt=salt,
        stored_key=stored_key,
        server_key=server_key,
        iterations=iterations
    )


def main():
    """
    Command-line utility to generate SCRAM credentials for storage in JSON configuration.

    Usage: python scram_credential_generator.py [password]

    If password is not provided, it will be read from stdin.

    Generates credentials for both SCRAM-SHA-256 and SCRAM-SHA-512.

    Output format (JSON):
    {
      "SCRAM-SHA-256": {
        "salt": "base64-encoded-salt",
        "stored_key": "base64-encoded-stored-key",
        "server_key": "base64-encoded-server-key",
        "iterations": 4096
      },
      "SCRAM-SHA-512": {
        "salt": "base64-encoded-salt",
        "stored_key": "base64-encoded-stored-key",
        "server_key": "base64-encoded-server-key",
        "iterations": 4096
      }
    }
    """
    # Get password from command line or prompt
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        try:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Error: No password provided", file=sys.stderr)
                sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print("\nError: No password provided", file=sys.stderr)
            sys.exit(1)

    # Generate credentials for both mechanisms
    mechanisms = [
        ("SCRAM-SHA-256", "sha256", 4096),
        ("SCRAM-SHA-512", "sha512", 4096),
    ]

    result = {}

    for mechanism_name, hash_name, iterations in mechanisms:
        try:
            credential = generate_scram_credential(password, iterations, hash_name)
            result[mechanism_name] = {
                "salt": base64.b64encode(credential.salt).decode('ascii'),
                "stored_key": base64.b64encode(credential.stored_key).decode('ascii'),
                "server_key": base64.b64encode(credential.server_key).decode('ascii'),
                "iterations": credential.iterations
            }
        except Exception as e:
            print(f"Error: Failed to generate credentials - {e}", file=sys.stderr)
            sys.exit(1)

    # Output JSON
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
