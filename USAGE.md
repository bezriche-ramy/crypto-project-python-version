# Crypto Client-Server Communication System

This project provides a secure client-server communication system supporting multiple encryption algorithms.

## Features

- **Multiple Encryption Algorithms**: AES (ECB/CBC), DES, RC4, Vigenère, Affine, Hill, Playfair
- **Default Test Keys**: Pre-configured keys for easy testing
- **Custom Key Support**: Option to input your own encryption keys
- **Multi-client Support**: Server can handle multiple simultaneous connections
- **Real-time Communication**: Instant encryption, transmission, and decryption

## Quick Start

### 1. Start the Server
```bash
python3 crypto_server.py
```
The server will start listening on `localhost:8888` and display supported algorithms.

### 2. Start the Client
```bash
python3 crypto_client.py
```
The client will connect to the server and show an interactive menu.

### 3. Send Encrypted Messages

1. Choose option `1` to send an encrypted message
2. Select an encryption method (1-9):
   - `1`: AES-ECB
   - `2`: AES-CBC  
   - `3`: DES-CBC
   - `4`: RC4
   - `5`: Vigenère
   - `6`: Affine
   - `7`: Hill
   - `8`: Playfair

3. Choose key option:
   - `1`: Use default test key (recommended for testing)
   - `2`: Enter custom key

4. Enter your message to encrypt and send
5. The server will decrypt and display the message

## Example Usage

### AES-ECB with Default Key
```
Select encryption method: 1
Choose key option: 1
Enter message: Hello World!
```

### Vigenère Cipher with Custom Key
```
Select encryption method: 5
Choose key option: 2
Enter key: MYSECRETKEY
Enter message: CRYPTOGRAPHY
```

## Supported Algorithms

| Algorithm | Key Type | Key Format | Notes |
|-----------|----------|------------|-------|
| AES-ECB/CBC | Binary | Hexadecimal (32/48/64 chars) | 128/192/256 bit |
| DES-CBC | Binary | Hexadecimal (16 chars) | 64 bit |
| RC4 | Binary | Hexadecimal (variable) | 8-2048 bit |
| Vigenère | Text | Alphabetic characters | Variable length |
| Affine | Numbers | Two integers (a,b) | gcd(a,26)=1 |
| Hill | Matrix | 2x2 matrix of integers | Invertible mod 26 |
| Playfair | Text | Alphabetic characters | Variable length |

## Default Test Keys

- **AES**: `00112233445566778899AABBCCDDEEFF`
- **DES**: `0123456789ABCDEF`
- **RC4**: `0123456789ABCDEF`
- **Vigenère**: `SECRETKEY`
- **Affine**: `a=5, b=8`
- **Hill**: `[[3,2],[5,7]]`
- **Playfair**: `SECRETKEY`

## Security Considerations

⚠️ **Important**: Default keys are for testing only. In production:

- Use cryptographically strong, randomly generated keys
- Implement secure key exchange protocols
- Consider authenticated encryption for message integrity
- Use proper key management practices

## Files

- `crypto_server.py`: Multi-algorithm decryption server
- `crypto_client.py`: Multi-algorithm encryption client
- `crypto_toolkit.py`: Core cryptographic functions
- `demo_test.py`: Demonstration script

## Dependencies

```bash
pip install pycryptodome
```

## Testing

Run the demo script for examples:
```bash
python3 demo_test.py
```
