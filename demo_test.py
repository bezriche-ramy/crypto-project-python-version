#!/usr/bin/env python3
"""
Demo Script for Crypto Client-Server Communication
==================================================

This script demonstrates the secure client-server communication system
with various encryption algorithms.
"""

import subprocess
import time
import sys
import os

def test_client_server():
    """Test the client-server communication system."""
    print("Crypto Client-Server Communication Demo")
    print("=" * 50)
    
    print("\nFeatures:")
    print("✓ Multi-algorithm encryption support")
    print("✓ AES (ECB/CBC), DES, RC4, Vigenère, Affine, Hill, Playfair")
    print("✓ Default test keys for easy testing")
    print("✓ Custom key input support")
    print("✓ Real-time encryption/decryption")
    print("✓ Multi-client support")
    
    print("\nTo test the system:")
    print("1. Start the server: python3 crypto_server.py")
    print("2. Start the client: python3 crypto_client.py")
    print("3. Choose an encryption method (1-9)")
    print("4. Choose to use default test keys (option 1) or enter custom keys")
    print("5. Enter your message to encrypt and send")
    print("6. The server will decrypt and display the message")
    
    print("\nExample Test Scenarios:")
    print("-" * 30)
    
    scenarios = [
        {
            "method": "AES-ECB",
            "key": "Default (00112233445566778899AABBCCDDEEFF)",
            "message": "Hello World!"
        },
        {
            "method": "Vigenère",
            "key": "Default (SECRETKEY)",
            "message": "CRYPTOISAWESOME"
        },
        {
            "method": "RC4",
            "key": "Default (0123456789ABCDEF)",
            "message": "Secure Communication"
        },
        {
            "method": "Hill",
            "key": "Default 2x2 matrix [[3,2],[5,7]]",
            "message": "MATHEMATICS"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {scenario['method']}")
        print(f"  Key: {scenario['key']}")
        print(f"  Message: {scenario['message']}")
        print(f"  Result: Message encrypted → sent → decrypted → displayed")
    
    print("\nSecurity Notes:")
    print("- Default keys are for testing only")
    print("- In production, use strong, randomly generated keys")
    print("- Keys should be securely exchanged between parties")
    print("- Consider using authenticated encryption for integrity")
    
    print("\nReady to test? Start the server and client in separate terminals!")

if __name__ == "__main__":
    test_client_server()
