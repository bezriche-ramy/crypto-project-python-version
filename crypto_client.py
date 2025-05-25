#!/usr/bin/env python3
"""
Crypto Client - Secure Communication Client
===========================================

This client script provides a secure communication interface that:
- Connects to the crypto server on localhost:8888
- Takes user input for messages
- Encrypts messages using AES ECB mode
- Sends encrypted messages to the server
- Receives and displays server responses

Author: Crypto Toolkit Project
"""

import socket
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import sys
import os
import json
import random
import string

# Add the current directory to Python path to import crypto_toolkit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import encryption functions from crypto_toolkit
try:
    from crypto_toolkit import (
        rc4_encrypt_decrypt, rc4_ksa, rc4_prga,
        HillCipher
    )
except ImportError:
    print("Warning: Could not import some crypto functions from crypto_toolkit.py")
    print("Some encryption methods may not be available.")

class CryptoClient:
    """
    A secure client that communicates with the crypto server using various encryption methods.
    """
    
    def __init__(self, host='localhost', port=8888):
        """
        Initialize the crypto client.
        
        Args:
            host (str): Server host address
            port (int): Server port number
        """
        self.host = host
        self.port = port
        self.client_socket = None
        self.connected = False
        
        # Available encryption methods
        self.encryption_methods = {
            '1': 'AES-ECB',
            '2': 'AES-CBC', 
            '3': 'DES-CBC',
            '4': 'RC4',
            '5': 'Vigenère',
            '6': 'Affine',
            '7': 'Hill',
            '8': 'Playfair',
            '9': 'One-Time Pad'
        }
        
        # Default keys for testing (in practice, keys should be securely exchanged)
        self.default_keys = {
            'AES-ECB': bytes.fromhex('00112233445566778899AABBCCDDEEFF'),  # 128-bit
            'AES-CBC': bytes.fromhex('00112233445566778899AABBCCDDEEFF'),  # 128-bit
            'DES-CBC': bytes.fromhex('0123456789ABCDEF'),  # 64-bit
            'RC4': bytes.fromhex('0123456789ABCDEF'),  # 64-bit
            'Vigenère': 'SECRETKEY',
            'Affine': (5, 8),
            'Hill': [[3, 2], [5, 7]],
            'Playfair': 'SECRETKEY',
            'One-Time Pad': bytes.fromhex('0123456789ABCDEF' * 8)  # 512-bit
        }
    
    def display_encryption_menu(self):
        """Display available encryption methods."""
        print("\nAvailable Encryption Methods:")
        print("=" * 40)
        for key, method in self.encryption_methods.items():
            print(f"{key}. {method}")
        print("0. Back to main menu")
        
    def get_user_key(self, method):
        """
        Get encryption key from user based on the selected method.
        
        Args:
            method (str): Selected encryption method
            
        Returns:
            bytes or str: Encryption key in appropriate format
        """
        print(f"\n{method} Key Configuration:")
        print("1. Use default test key (recommended for testing)")
        print("2. Enter custom key")
        
        key_choice = input("Choose option (1-2): ").strip()
        
        if key_choice == "1":
            # Use default test key
            default_key = self.default_keys.get(method)
            if default_key is None:
                print("Error: No default key available for this method")
                return None
            
            print(f"Using default key for {method}")
            if isinstance(default_key, bytes):
                print(f"Key (hex): {default_key.hex()}")
            else:
                print(f"Key: {default_key}")
            
            return default_key
            
        elif key_choice == "2":
            # Get custom key from user
            return self._get_custom_key(method)
        else:
            print("Invalid choice")
            return None
    
    def _get_custom_key(self, method):
        """Get custom key from user input."""
        if method in ['AES-ECB', 'AES-CBC']:
            print(f"\n{method} Key Input:")
            print("Enter key as hexadecimal (32 chars for 128-bit, 48 for 192-bit, 64 for 256-bit)")
            print("Example: 00112233445566778899AABBCCDDEEFF")
            key_input = input("Key: ").strip()
            try:
                key = bytes.fromhex(key_input)
                if len(key) not in [16, 24, 32]:
                    print("Error: Key must be 16, 24, or 32 bytes")
                    return None
                return key
            except ValueError:
                print("Error: Invalid hexadecimal key")
                return None
                
        elif method == 'DES-CBC':
            print(f"\n{method} Key Input:")
            print("Enter key as hexadecimal (16 chars for 64-bit)")
            print("Example: 0123456789ABCDEF")
            key_input = input("Key: ").strip()
            try:
                key = bytes.fromhex(key_input)
                if len(key) != 8:
                    print("Error: DES key must be exactly 8 bytes")
                    return None
                return key
            except ValueError:
                print("Error: Invalid hexadecimal key")
                return None
                
        elif method == 'RC4':
            print(f"\n{method} Key Input:")
            print("Enter key as hexadecimal (variable length, 1-256 bytes)")
            print("Example: 0123456789ABCDEF")
            key_input = input("Key: ").strip()
            try:
                key = bytes.fromhex(key_input)
                if len(key) == 0:
                    print("Error: Key cannot be empty")
                    return None
                return key
            except ValueError:
                print("Error: Invalid hexadecimal key")
                return None
                
        elif method in ['Vigenère', 'Playfair']:
            print(f"\n{method} Key Input:")
            print("Enter alphabetic key (letters only)")
            print("Example: SECRETKEY")
            key = input("Key: ").strip().upper()
            if not key.isalpha():
                print("Error: Key must contain only letters")
                return None
            return key
            
        elif method == 'Affine':
            print(f"\n{method} Key Input:")
            print("Enter two integers 'a' and 'b' where gcd(a,26)=1")
            try:
                a = int(input("a = "))
                b = int(input("b = "))
                from math import gcd
                if gcd(a, 26) != 1:
                    print("Error: 'a' must be coprime with 26")
                    return None
                return (a, b)
            except ValueError:
                print("Error: Invalid integer input")
                return None
                
        elif method == 'Hill':
            print(f"\n{method} Key Input:")
            print("Enter 2x2 matrix elements (4 integers between 0-25)")
            try:
                matrix = []
                for i in range(2):
                    row = []
                    for j in range(2):
                        val = int(input(f"Matrix[{i}][{j}]: ")) % 26
                        row.append(val)
                    matrix.append(row)
                return matrix
            except ValueError:
                print("Error: Invalid matrix input")
                return None
                
        elif method == 'One-Time Pad':
            print(f"\n{method} Key Input:")
            print("Enter key as hexadecimal (must be at least as long as message)")
            print("Example: 0123456789ABCDEF...")
            key_input = input("Key: ").strip()
            try:
                key = bytes.fromhex(key_input)
                if len(key) == 0:
                    print("Error: Key cannot be empty")
                    return None
                return key
            except ValueError:
                print("Error: Invalid hexadecimal key")
                return None
        
        return None
        
    def encrypt_message(self, message, method, key):
        """
        Encrypt a message using the specified method and key.
        
        Args:
            message (str): Plain text message to encrypt
            method (str): Encryption method
            key: Encryption key (type varies by method)
            
        Returns:
            tuple: (encrypted_data, metadata) or (None, None) if encryption fails
        """
        try:
            if method == 'AES-ECB':
                message_bytes = message.encode('utf-8')
                cipher = AES.new(key, AES.MODE_ECB)
                ciphertext = cipher.encrypt(pad(message_bytes, AES.block_size))
                return ciphertext.hex(), {'method': 'AES-ECB', 'key_size': len(key)}
                
            elif method == 'AES-CBC':
                message_bytes = message.encode('utf-8')
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(message_bytes, AES.block_size))
                encrypted = iv + ciphertext
                return encrypted.hex(), {'method': 'AES-CBC', 'key_size': len(key), 'iv_size': len(iv)}
                
            elif method == 'DES-CBC':
                message_bytes = message.encode('utf-8')
                iv = get_random_bytes(8)
                cipher = DES.new(key, DES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(message_bytes, DES.block_size))
                encrypted = iv + ciphertext
                return encrypted.hex(), {'method': 'DES-CBC', 'key_size': len(key), 'iv_size': len(iv)}
                
            elif method == 'RC4':
                message_bytes = message.encode('utf-8')
                encrypted = rc4_encrypt_decrypt(key, message_bytes)
                return encrypted.hex(), {'method': 'RC4', 'key_size': len(key)}
                
            elif method == 'Vigenère':
                encrypted = ""
                key_index = 0
                
                for char in message:
                    if char.isalpha():
                        # Handle letters while preserving case
                        is_upper = char.isupper()
                        base = ord('A' if is_upper else 'a')
                        shift = ord(key[key_index % len(key)].upper()) - ord('A')
                        encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + base)
                        encrypted += encrypted_char
                        key_index += 1
                    elif char.isdigit():
                        # Handle numbers (0-9) using same key position
                        shift = ord(key[key_index % len(key)].upper()) - ord('A')
                        # Map A-Z (0-25) to smaller shift for numbers (0-9)
                        number_shift = shift % 10
                        encrypted_char = str((int(char) + number_shift) % 10)
                        encrypted += encrypted_char
                        key_index += 1
                    else:
                        # Preserve special characters
                        encrypted += char
                
                return encrypted.encode('utf-8').hex(), {'method': 'Vigenère', 'key': key}
                
            elif method == 'Affine':
                a, b = key
                # Keep both letters and numbers, convert to uppercase
                message_clean = ''.join(c.upper() for c in message if c.isalnum())
                if not message_clean:
                    raise ValueError("Message must contain letters or numbers for Affine cipher")
                
                encrypted = ""
                modulus = 36  # Use modulo 36 for letters (0-25) and numbers (26-35)
                
                for char in message_clean:
                    if char.isalpha():
                        # Handle letters (A-Z: 0-25)
                        val = ord(char) - ord('A')
                        enc_val = (a * val + b) % modulus
                        if enc_val < 26:
                            encrypted += chr(enc_val + ord('A'))
                        else:
                            encrypted += str(enc_val - 26)
                    elif char.isdigit():
                        # Handle numbers (0-9: 26-35)
                        val = int(char) + 26  # Shift numbers after letters
                        enc_val = (a * val + b) % modulus
                        if enc_val < 26:
                            encrypted += chr(enc_val + ord('A'))
                        else:
                            encrypted += str(enc_val - 26)
                
                return encrypted.encode('utf-8').hex(), {
                    'method': 'Affine',
                    'a': a,
                    'b': b,
                    'use_extended': True  # Flag for extended mode (letters + numbers)
                }
                
            elif method == 'Hill':
                # Split message into alphanumeric and non-alphanumeric while tracking positions
                chars = []
                char_positions = []
                preserved_chars = []
                
                for i, char in enumerate(message):
                    if char.isalnum():
                        # Convert both letters and numbers to 0-35 range
                        if char.isalpha():
                            val = ord(char.upper()) - ord('A')
                        else:  # isdigit
                            val = int(char) + 26  # Map 0-9 to 26-35
                        chars.append(val)
                        char_positions.append(i)
                    else:
                        preserved_chars.append((i, char))
                
                # Pad the sequence if needed
                if len(chars) % 2 != 0:
                    chars.append(35)  # Use '9' (35) as padding
                    char_positions.append(len(message))
                
                # Encrypt pairs of characters (letters and numbers)
                hill_encrypted = ""
                for i in range(0, len(chars), 2):
                    pair = [chars[i], chars[i+1]]
                    encrypted_pair = [
                        sum(key[0][j] * pair[j] for j in range(2)) % 36,
                        sum(key[1][j] * pair[j] for j in range(2)) % 36
                    ]
                    
                    # Convert back to letters and numbers
                    for val in encrypted_pair:
                        if val < 26:
                            hill_encrypted += chr(val + ord('A'))
                        else:
                            hill_encrypted += str(val - 26)
                
                # Reconstruct original message with encrypted letters and preserved characters
                result = [''] * (len(message) + (1 if len(hill_encrypted) > len(message) else 0))
                # Fill in encrypted letters
                for pos, enc_char in zip(letter_positions, hill_encrypted):
                    result[pos] = enc_char
                # Fill in preserved characters
                for pos, char in preserved_chars:
                    result[pos] = char
                
                encrypted = ''.join(c for c in result if c is not None)
                return encrypted.encode('utf-8').hex(), {'method': 'Hill', 'matrix': key}
                
            elif method == 'Playfair':
                # Create Playfair matrix
                matrix = self.create_playfair_matrix(key)
                
                # Keep track of non-letter positions and characters
                preserved_chars = []
                letter_positions = []
                message_clean = ""
                
                # Collect letters and preserve other characters
                for i, char in enumerate(message):
                    if char.isalpha():
                        c = char.upper()
                        if c == 'J':
                            c = 'I'
                        message_clean += c
                        letter_positions.append(i)
                    else:
                        preserved_chars.append((i, char))
                
                # Prepare text for Playfair
                pairs = self.prepare_playfair_text(message_clean)
                
                # Encrypt only the letters
                playfair_encrypted = ""
                for pair in pairs:
                    p1, p2 = pair[0], pair[1]
                    pos1, pos2 = self.find_playfair_positions(matrix, p1, p2)
                    
                    if pos1[0] == pos2[0]:  # Same row
                        playfair_encrypted += matrix[pos1[0]][(pos1[1] + 1) % 5]
                        playfair_encrypted += matrix[pos2[0]][(pos2[1] + 1) % 5]
                    elif pos1[1] == pos2[1]:  # Same column
                        playfair_encrypted += matrix[(pos1[0] + 1) % 5][pos1[1]]
                        playfair_encrypted += matrix[(pos2[0] + 1) % 5][pos2[1]]
                    else:  # Rectangle
                        playfair_encrypted += matrix[pos1[0]][pos2[1]]
                        playfair_encrypted += matrix[pos2[0]][pos1[1]]
                
                # Reconstruct original message with encrypted letters and preserved characters
                result = [''] * (len(message) + (1 if len(playfair_encrypted) > len(message) else 0))
                # Fill in encrypted letters
                for pos, enc_char in zip(letter_positions, playfair_encrypted):
                    result[pos] = enc_char
                # Fill in preserved characters
                for pos, char in preserved_chars:
                    result[pos] = char
                # Fill any remaining positions (padding)
                if len(playfair_encrypted) > len(message):
                    result[len(message)] = playfair_encrypted[-1]
                
                encrypted = ''.join(c for c in result if c is not None)
                return encrypted.encode('utf-8').hex(), {'method': 'Playfair', 'key': key}
                
            elif method == 'One-Time Pad':
                message_bytes = message.encode('utf-8')
                if len(key) < len(message_bytes):
                    raise ValueError("Key must be at least as long as the message")
                
                encrypted = bytes(m ^ k for m, k in zip(message_bytes, key))
                return encrypted.hex(), {'method': 'One-Time Pad', 'key_size': len(key)}
                
            else:
                raise ValueError(f"Unknown encryption method: {method}")
                
        except Exception as e:
            print(f"Encryption error: {e}")
            return None, None
    
    def create_playfair_matrix(self, key):
        """Create a 5x5 Playfair matrix from a key."""
        key = key.replace('J', 'I')  # J and I share same position
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        
        # Remove duplicates while preserving order
        seen = set()
        unique_key = ""
        for char in key + alphabet:
            if char not in seen:
                unique_key += char
                seen.add(char)
        
        # Create 5x5 matrix
        matrix = []
        for i in range(5):
            row = []
            for j in range(5):
                row.append(unique_key[i * 5 + j])
            matrix.append(row)
        
        return matrix
    
    def prepare_playfair_text(self, text):
        """Prepare text for Playfair encryption by creating pairs."""
        text = text.replace('J', 'I')
        pairs = []
        i = 0
        while i < len(text):
            if i + 1 < len(text) and text[i] != text[i + 1]:
                pairs.append(text[i:i+2])
                i += 2
            else:
                if i + 1 < len(text):
                    pairs.append(text[i] + 'X')
                    i += 1
                else:
                    pairs.append(text[i] + 'X')
                    i += 1
        return pairs
    
    def find_playfair_positions(self, matrix, char1, char2):
        """Find positions of two characters in the Playfair matrix."""
        pos1 = pos2 = None
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char1:
                    pos1 = (i, j)
                if matrix[i][j] == char2:
                    pos2 = (i, j)
        return pos1, pos2
    
    def connect_to_server(self):
        """
        Establish connection to the crypto server.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.connected = True
            print(f"Connected to server at {self.host}:{self.port}")
            return True
            
        except ConnectionRefusedError:
            print(f"Error: Could not connect to server at {self.host}:{self.port}")
            print("Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def disconnect_from_server(self):
        """
        Disconnect from the server and clean up resources.
        """
        if self.connected and self.client_socket:
            try:
                # Send quit message to server
                self.client_socket.send("quit".encode('utf-8'))
                self.client_socket.close()
            except:
                pass
            finally:
                self.connected = False
                print("Disconnected from server")
    
    def send_message(self, message, method, key):
        """
        Encrypt and send a message to the server.
        
        Args:
            message (str): Plain text message to send
            method (str): Encryption method to use
            key: Encryption key
            
        Returns:
            str: Server response or None if sending fails
        """
        if not self.connected:
            print("Error: Not connected to server")
            return None
            
        try:
            # Encrypt the message
            encrypted_data, metadata = self.encrypt_message(message, method, key)
            
            if not encrypted_data or not metadata:
                print("Failed to encrypt message")
                return None
            
            print(f"Original message: {message}")
            print(f"Encryption method: {method}")
            print(f"Encrypted (hex): {encrypted_data}")
            
            # Create message packet with metadata
            message_packet = {
                'encrypted_data': encrypted_data,
                'metadata': metadata
            }
            
            # Send message packet as JSON to server
            packet_json = json.dumps(message_packet)
            self.client_socket.send(packet_json.encode('utf-8'))
            
            # Receive server response
            response = self.client_socket.recv(4096).decode('utf-8')
            return response
            
        except Exception as e:
            print(f"Error sending message: {e}")
            return None
    
    def run_interactive_menu(self):
        """
        Run the interactive client menu for user interaction.
        """
        print("\nCrypto Client - Interactive Menu")
        print("=" * 40)
        
        while self.connected:
            print("\nMain Options:")
            print("1. Send encrypted message")
            print("2. Disconnect and quit")
            
            choice = input("\nEnter your choice (1-2): ").strip()
            
            if choice == "1":
                # Show encryption methods menu
                self.display_encryption_menu()
                
                # Get encryption method choice
                method_choice = input("\nSelect encryption method (0-9): ").strip()
                
                if method_choice == "0":
                    continue
                    
                if method_choice not in self.encryption_methods:
                    print("Invalid choice. Please try again.")
                    continue
                
                method = self.encryption_methods[method_choice]
                print(f"\nSelected method: {method}")
                
                # Get encryption key
                key = self.get_user_key(method)
                if key is None:
                    print("Failed to get valid key. Please try again.")
                    continue
                
                # Get message
                message = input("\nEnter message to encrypt and send: ").strip()
                
                if not message:
                    print("Error: Empty message")
                    continue
                
                print(f"\nSending encrypted message using {method}...")
                response = self.send_message(message, method, key)
                
                if response:
                    print(f"Server response: {response}")
                else:
                    print("Failed to send message or receive response")
                    
            elif choice == "2":
                print("\nDisconnecting from server...")
                break
                
            else:
                print("Invalid choice. Please enter 1 or 2.")
        
        self.disconnect_from_server()

def main():
    """
    Main function to start the crypto client.
    """
    print("Crypto Client - Secure Communication Client")
    print("=" * 50)
    print("Supporting multiple encryption algorithms:")
    print("AES (ECB/CBC), DES, RC4, Vigenère, Affine, Hill, Playfair, One-Time Pad")
    print("=" * 50)
    
    # Create client instance
    client = CryptoClient()
    
    try:
        # Connect to server
        if client.connect_to_server():
            # Run interactive menu
            client.run_interactive_menu()
        else:
            print("Failed to connect to server. Exiting.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        client.disconnect_from_server()
    except Exception as e:
        print(f"Client error: {e}")
        client.disconnect_from_server()
        sys.exit(1)

if __name__ == "__main__":
    main()
