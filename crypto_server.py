#!/usr/bin/env python3
"""
Crypto Server - Secure Communication Server
===========================================

This server script provides a secure communication endpoint that:
- Listens on localhost:8888 for incoming client connections
- Receives encrypted messages from clients
- Decrypts messages using AES ECB mode
- Displays decrypted messages
- Handles multiple client connections concurrently

Author: Crypto Toolkit Project
"""

import socket
import threading
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
import sys
import os
import json
from math import gcd

# Add the current directory to Python path to import crypto_toolkit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import encryption functions from crypto_toolkit
try:
    from crypto_toolkit import (
        rc4_encrypt_decrypt, rc4_ksa, rc4_prga
    )
except ImportError:
    print("Warning: Could not import some crypto functions from crypto_toolkit.py")
    print("Some decryption methods may not be available.")

# Fixed AES key for backward compatibility (16 bytes for AES-128)
DEFAULT_AES_KEY = bytes.fromhex('00112233445566778899AABBCCDDEEFF')  # 16 bytes key

class CryptoServer:
    """
    A secure server that handles encrypted communications using various encryption methods.
    """
    
    def __init__(self, host='localhost', port=8888):
        """
        Initialize the crypto server.
        
        Args:
            host (str): Server host address
            port (int): Server port number
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
    def decrypt_message(self, encrypted_hex, metadata):
        """
        Decrypt a message using the specified method and metadata.
        
        Args:
            encrypted_hex (str): Encrypted message in hexadecimal format
            metadata (dict): Encryption metadata including method and parameters
            
        Returns:
            str: Decrypted message or None if decryption fails
        """
        try:
            method = metadata.get('method', 'AES-ECB')
            print(f"Decrypting using method: {method}")
            
            if method == 'AES-ECB':
                return self.decrypt_aes_ecb(encrypted_hex, metadata)
            elif method == 'AES-CBC':
                return self.decrypt_aes_cbc(encrypted_hex, metadata)
            elif method == 'DES-CBC':
                return self.decrypt_des_cbc(encrypted_hex, metadata)
            elif method == 'RC4':
                return self.decrypt_rc4(encrypted_hex, metadata)
            elif method == 'Vigenère':
                return self.decrypt_vigenere(encrypted_hex, metadata)
            elif method == 'Affine':
                return self.decrypt_affine(encrypted_hex, metadata)
            elif method == 'Hill':
                return self.decrypt_hill(encrypted_hex, metadata)
            elif method == 'Playfair':
                return self.decrypt_playfair(encrypted_hex, metadata)
            else:
                print(f"Unknown decryption method: {method}")
                return None
                
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def decrypt_aes_ecb(self, encrypted_hex, metadata):
        """Decrypt AES ECB encrypted message."""
        try:
            ciphertext = bytes.fromhex(encrypted_hex)
            # Use default key for now (in practice, key should be securely exchanged)
            key = DEFAULT_AES_KEY
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"AES-ECB decryption error: {e}")
            return None
    
    def decrypt_aes_cbc(self, encrypted_hex, metadata):
        """Decrypt AES CBC encrypted message."""
        try:
            encrypted = bytes.fromhex(encrypted_hex)
            iv_size = metadata.get('iv_size', 16)
            if len(encrypted) <= iv_size:
                raise ValueError("Encrypted data too short to contain IV and ciphertext")
            
            iv = encrypted[:iv_size]
            ciphertext = encrypted[iv_size:]
            # Use default key for now (in practice, key should be securely exchanged)
            key = DEFAULT_AES_KEY
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"AES-CBC decryption error: {e}")
            return None
    
    def decrypt_des_cbc(self, encrypted_hex, metadata):
        """Decrypt DES CBC encrypted message."""
        encrypted = bytes.fromhex(encrypted_hex)
        iv_size = metadata.get('iv_size', 8)
        iv = encrypted[:iv_size]
        ciphertext = encrypted[iv_size:]
        # Use default DES key (in practice, key should be securely exchanged)
        des_key = bytes.fromhex('0123456789ABCDEF')  # Default test key
        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return decrypted.decode('utf-8')
    
    def decrypt_rc4(self, encrypted_hex, metadata):
        """Decrypt RC4 encrypted message."""
        ciphertext = bytes.fromhex(encrypted_hex)
        # Use default RC4 key (in practice, key should be securely exchanged)
        rc4_key = bytes.fromhex('0123456789ABCDEF')  # Default test key
        decrypted = rc4_encrypt_decrypt(rc4_key, ciphertext)
        return decrypted.decode('utf-8')
    
    def decrypt_vigenere(self, encrypted_hex, metadata):
        """Decrypt Vigenère cipher encrypted message."""
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        encrypted_text = encrypted_bytes.decode('utf-8')
        key = metadata.get('key', 'KEY')
        
        full_key = (key * (len(encrypted_text)//len(key) + 1))[:len(encrypted_text)]
        key_index = 0
        decrypted = ""
        
        for char in encrypted_text:
            if char.isalpha():
                # Handle letters while preserving case
                is_upper = char.isupper()
                base = ord('A' if is_upper else 'a')
                shift = ord(full_key[key_index].upper()) - ord('A')
                decrypted_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + base)
                decrypted += decrypted_char
                key_index += 1
            elif char.isdigit():
                # Handle numbers (0-9) using same key position
                shift = ord(full_key[key_index].upper()) - ord('A')
                # Map A-Z (0-25) to smaller shift for numbers (0-9)
                number_shift = shift % 10
                decrypted_char = str((int(char) - number_shift) % 10)
                decrypted += decrypted_char
                key_index += 1
            else:
                # Preserve special characters
                decrypted += char
        
        return decrypted
    
    def decrypt_affine(self, encrypted_hex, metadata):
        """Decrypt Affine cipher encrypted message."""
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        encrypted_text = encrypted_bytes.decode('utf-8')
        a = metadata.get('a', 1)
        b = metadata.get('b', 0)
        use_extended = metadata.get('use_extended', True)  # Support for numbers
        
        if use_extended:
            # Extended mode (letters + numbers): mod 36
            modulus = 36
            # Find modular multiplicative inverse of a
            a_inv = None
            for i in range(modulus):
                if (a * i) % modulus == 1:
                    a_inv = i
                    break
            
            if a_inv is None:
                raise ValueError("Cannot decrypt: 'a' is not invertible mod 36")
            
            decrypted = ""
            for char in encrypted_text:
                if char.isalpha():
                    # Handle letters (A-Z: 0-25)
                    val = ord(char.upper()) - ord('A')
                    dec_val = (a_inv * (val - b)) % modulus
                    if dec_val < 26:
                        decrypted += chr(dec_val + ord('A'))
                    else:
                        # Convert to number (26-35 → 0-9)
                        decrypted += str(dec_val - 26)
                elif char.isdigit():
                    # Handle numbers (0-9: 26-35)
                    val = int(char) + 26  # Shift numbers after letters
                    dec_val = (a_inv * (val - b)) % modulus
                    if dec_val < 26:
                        decrypted += chr(dec_val + ord('A'))
                    else:
                        decrypted += str(dec_val - 26)
                else:
                    # Keep other characters unchanged
                    decrypted += char
        else:
            # Legacy mode (letters only): mod 26
            modulus = 26
            # Find modular multiplicative inverse of a
            a_inv = None
            for i in range(modulus):
                if (a * i) % modulus == 1:
                    a_inv = i
                    break
            
            if a_inv is None:
                raise ValueError("Cannot decrypt: 'a' is not invertible mod 26")
            
            decrypted = ""
            for char in encrypted_text:
                if char.isalpha():
                    val = ord(char.upper()) - ord('A')
                    dec_val = (a_inv * (val - b)) % modulus
                    decrypted += chr(dec_val + ord('A'))
                else:
                    decrypted += char
                    
        return decrypted
    
    def decrypt_hill(self, encrypted_hex, metadata):
        """Decrypt Hill cipher encrypted message."""
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            encrypted_text = encrypted_bytes.decode('utf-8')
            matrix = metadata.get('matrix', [[1, 0], [0, 1]])
            
            # Validate matrix structure
            if not isinstance(matrix, list) or len(matrix) != 2 or not all(isinstance(row, list) and len(row) == 2 for row in matrix):
                raise ValueError("Invalid Hill cipher matrix format - must be 2x2")
            
            # Calculate determinant modulo 36
            det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 36
            
            # Check if matrix is invertible (gcd(det, 36) = 1)
            from math import gcd
            if gcd(det, 36) != 1:
                raise ValueError(f"Matrix is not invertible mod 36 (det={det}, gcd(det,36)={gcd(det,36)})")
            
            # Find modular multiplicative inverse of determinant
            det_inv = None
            for i in range(36):
                if (det * i) % 36 == 1:
                    det_inv = i
                    break
            
            if det_inv is None:
                raise ValueError("Could not find modular inverse of determinant")
            
            # Calculate inverse matrix
            inv_matrix = [
                [(det_inv * matrix[1][1]) % 36, (det_inv * (-matrix[0][1] % 36)) % 36],
                [(det_inv * (-matrix[1][0] % 36)) % 36, (det_inv * matrix[0][0]) % 36]
            ]
            
            # Split message into alphanumeric and non-alphanumeric while tracking positions
            chars = []
            char_positions = []
            preserved_chars = []
            
            for i, char in enumerate(encrypted_text):
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
            
            # Pad the message if needed
            if len(chars) % 2 != 0:
                chars.append(35)  # Use '9' (35) as padding
                char_positions.append(len(encrypted_text))
            
            # Process pairs for decryption
            decrypted_chars = []
            for i in range(0, len(chars), 2):
                if i + 1 >= len(chars):  # Safety check
                    break
                    
                pair = [chars[i], chars[i+1]]
                
                # Decrypt the pair using the inverse matrix
                decrypted_pair = [
                    (inv_matrix[0][0] * pair[0] + inv_matrix[0][1] * pair[1]) % 36,
                    (inv_matrix[1][0] * pair[0] + inv_matrix[1][1] * pair[1]) % 36
                ]
                
                # Convert back to letters and numbers
                for val in decrypted_pair:
                    if val < 26:
                        decrypted_chars.append(chr(val + ord('A')))
                    else:
                        decrypted_chars.append(str(val - 26))
            
            # Reconstruct original message with decrypted characters and preserved characters
            result = [''] * (len(encrypted_text) + (1 if len(decrypted_chars) > len(encrypted_text) else 0))
            
            # Fill in decrypted characters
            for pos, dec_char in zip(char_positions, decrypted_chars):
                result[pos] = dec_char
                
            # Fill in preserved characters
            for pos, char in preserved_chars:
                result[pos] = char
                
            decrypted = ''.join(c for c in result if c)
            
            return decrypted
        except Exception as e:
            print(f"Hill cipher decryption error: {e}")
            return None
    
    def decrypt_playfair(self, encrypted_hex, metadata):
        """Decrypt Playfair cipher encrypted message."""
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            encrypted_text = encrypted_bytes.decode('utf-8')
            key = metadata.get('key', 'KEY')
            
            # Filter out non-alphabetic characters
            encrypted_letters = ''.join(c for c in encrypted_text if c.isalpha())
            
            # Check if we have enough characters to decrypt
            if len(encrypted_letters) < 2 or len(encrypted_letters) % 2 != 0:
                raise ValueError("Invalid Playfair ciphertext length")
                
            # Create Playfair matrix
            matrix = self.create_playfair_matrix(key)
            
            # Track original positions of alphanumeric and non-alphanumeric characters
            letter_positions = [i for i, c in enumerate(encrypted_text) if c.isalpha()]
            preserved_chars = [(i, c) for i, c in enumerate(encrypted_text) if not c.isalpha()]
            
            # Decrypt only the letters
            decrypted_letters = ""
            pairs = []
            for i in range(0, len(encrypted_letters), 2):
                if i + 1 < len(encrypted_letters):  # Make sure we have a complete pair
                    pairs.append(encrypted_letters[i:i+2])
            
            for pair in pairs:
                p1, p2 = pair[0], pair[1]
                pos1, pos2 = self.find_playfair_positions(matrix, p1, p2)
                
                if not pos1 or not pos2:
                    raise ValueError(f"Character not found in Playfair matrix: {p1} or {p2}")
                    
                if pos1[0] == pos2[0]:  # Same row
                    decrypted_letters += matrix[pos1[0]][(pos1[1] - 1) % 5]
                    decrypted_letters += matrix[pos2[0]][(pos2[1] - 1) % 5]
                elif pos1[1] == pos2[1]:  # Same column
                    decrypted_letters += matrix[(pos1[0] - 1) % 5][pos1[1]]
                    decrypted_letters += matrix[(pos2[0] - 1) % 5][pos2[1]]
                else:  # Rectangle
                    decrypted_letters += matrix[pos1[0]][pos2[1]]
                    decrypted_letters += matrix[pos2[0]][pos1[1]]
            
            # Reconstruct original message format with decrypted letters and preserved characters
            result = [''] * len(encrypted_text)
            
            # Fill in decrypted letters
            for pos, dec_char in zip(letter_positions, decrypted_letters[:len(letter_positions)]):
                result[pos] = dec_char
                
            # Fill in preserved characters
            for pos, char in preserved_chars:
                result[pos] = char
                
            decrypted = ''.join(result)
            
            # Remove any 'X' characters used for padding (common in Playfair)
            if decrypted.endswith('X'):
                decrypted = decrypted[:-1]
                
            return decrypted
        except Exception as e:
            print(f"Playfair decryption error: {e}")
            return None
    

    
    def create_playfair_matrix(self, key):
        """Create a 5x5 Playfair matrix from a key."""
        key = key.replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        seen = set()
        unique_key = ""
        for char in key + alphabet:
            if char not in seen:
                unique_key += char
                seen.add(char)
        
        matrix = []
        for i in range(5):
            row = []
            for j in range(5):
                row.append(unique_key[i * 5 + j])
            matrix.append(row)
        
        return matrix
    
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
    
    def handle_client(self, client_socket, client_address):
        """
        Handle communication with a connected client.
        
        Args:
            client_socket: Client socket object
            client_address: Client address tuple (host, port)
        """
        print(f"New client connected from {client_address[0]}:{client_address[1]}")
        
        try:
            while self.running:
                # Receive encrypted message from client
                data = client_socket.recv(4096).decode('utf-8').strip()
                
                if not data:
                    break
                    
                if data.lower() == 'quit':
                    print(f"Client {client_address[0]}:{client_address[1]} disconnected")
                    break
                
                print(f"\nReceived data from {client_address[0]}:{client_address[1]}:")
                
                try:
                    # Parse the JSON message packet
                    message_packet = json.loads(data)
                    encrypted_hex = message_packet.get('encrypted_data')
                    metadata = message_packet.get('metadata', {})
                    
                    print(f"Encryption method: {metadata.get('method', 'Unknown')}")
                    print(f"Encrypted (hex): {encrypted_hex}")
                    
                    # Decrypt the message
                    decrypted_message = self.decrypt_message(encrypted_hex, metadata)
                    
                    if decrypted_message:
                        print(f"Decrypted message: {decrypted_message}")
                        
                        # Send acknowledgment back to client
                        ack_message = f"Message received and decrypted: {decrypted_message}"
                        client_socket.send(ack_message.encode('utf-8'))
                    else:
                        print("Failed to decrypt message")
                        error_message = "Error: Failed to decrypt message"
                        client_socket.send(error_message.encode('utf-8'))
                        
                except json.JSONDecodeError:
                    print("Error: Invalid JSON message format")
                    error_message = "Error: Invalid message format"
                    client_socket.send(error_message.encode('utf-8'))
                    
        except ConnectionResetError:
            print(f"Client {client_address[0]}:{client_address[1]} disconnected unexpectedly")
        except Exception as e:
            print(f"Error handling client {client_address[0]}:{client_address[1]}: {e}")
        finally:
            client_socket.close()
            print(f"Connection with {client_address[0]}:{client_address[1]} closed")
    
    def start_server(self):
        """
        Start the server and listen for incoming connections.
        """
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address and port
            self.server_socket.bind((self.host, self.port))
            
            # Start listening
            self.server_socket.listen(5)
            self.running = True
            
            print(f"Server listening on port {self.port}...")
            print("Press Ctrl+C to stop the server")
            
            while self.running:
                try:
                    # Accept incoming connections
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create a new thread to handle the client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")
                        break
                        
        except KeyboardInterrupt:
            print("\nShutting down server...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop_server()
    
    def stop_server(self):
        """
        Stop the server and clean up resources.
        """
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("Server stopped")

def main():
    """
    Main function to start the crypto server.
    """
    print("Crypto Server - Secure Communication Server")
    print("=" * 50)
    print(f"Using default AES key: {DEFAULT_AES_KEY.hex()}")
    print("Supports multiple encryption algorithms:")
    print("AES (ECB/CBC), DES, RC4, Vigenère, Affine, Hill, Playfair")
    print("=" * 50)
    
    # Create and start the server
    server = CryptoServer()
    
    try:
        server.start_server()
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
