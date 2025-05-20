# IMPORTANT: Before running this script, activate the virtual environment with:
# source venv/bin/activate
# This ensures all cryptographic libraries are available.

import sys
import random
import string
import hashlib
from math import gcd
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import numpy as np
from typing import List, Tuple

# French letter frequencies (in percentage)
FRENCH_FREQUENCIES = {
    'E': 14.7, 'A': 9.0, 'S': 7.9, 'I': 7.3, 'N': 7.1,
    'T': 7.0, 'R': 6.6, 'U': 6.3, 'L': 5.5, 'O': 5.4,
    'D': 3.7, 'C': 3.3, 'P': 3.0, 'M': 2.9, 'V': 1.6,
    'H': 0.9, 'G': 0.9, 'F': 1.1, 'B': 1.1, 'Q': 1.4,
    'X': 0.4, 'J': 0.3, 'Y': 0.3, 'K': 0.1, 'W': 0.1,
    'Z': 0.1
}

def main_menu():
    while True:
        print("\nCryptographic Toolkit Main Menu")
        print("1. Affine Cipher")
        print("2. Frequency Analysis")
        print("3. Hill Cipher")
        print("4. Playfair Cipher")
        print("5. Vigenère Cipher")
        print("6. One-Time Pad")
        print("7. Index of Coincidence")
        print("8. RC4")
        print("9. AES")
        print("10. DES")
        print("11. ElGamal")
        print("12. Block Cipher Modes (ECB & CBC)")
        print("13. RSA")
        print("14. SHA-256 Hash Function")
        print("15. Digital Signature (RSA)")
        print("16. Crypto Protocols (Theory only)")
        print("17. Homomorphic Encryption (Conceptual Demo)")
        print("18. Shamir Secret Sharing")
        print("0. Exit")

        choice = input("Select an option (0-18): ")

        if choice == "0":
            print("Exiting program...")
            break
        elif choice == "1":
            affine_cipher_menu()
        elif choice == "2":
            frequency_analysis()
        elif choice == "3":
            hill_cipher_menu()
        elif choice == "4":
            playfair_cipher_menu()
        elif choice == "5":
            vigenere_cipher_menu()
        elif choice == "6":
            one_time_pad_menu()
        elif choice == "7":
            index_of_coincidence()
        elif choice == "8":
            rc4_menu()
        elif choice == "9":
            aes_menu()
        elif choice == "10":
            des_menu()
        elif choice == "11":
            elgamal_menu()
        elif choice == "12":
            block_cipher_modes_menu()
        elif choice == "13":
            rsa_menu()
        elif choice == "14":
            sha256_hash_function()
        elif choice == "15":
            digital_signature_menu()
        elif choice == "16":
            crypto_protocols_theory()
        elif choice == "17":
            homomorphic_encryption_demo()
        elif choice == "18":
            shamir_secret_sharing_menu()
        else:
            print("Invalid choice. Please try again.")

def affine_cipher_menu():
    print("\nAffine Cipher Menu")
    while True:
        print("1. Generate Key")
        print("2. Encrypt a Message")
        print("3. Decrypt a Message")
        print("0. Back to Main Menu")

        choice = input("Select an option (0-3): ")

        if choice == "0":
            break
        elif choice == "1":
            generate_affine_key()
        elif choice == "2":
            encrypt_affine()
        elif choice == "3":
            decrypt_affine()
        else:
            print("Invalid choice. Please try again.")

def generate_affine_key():
    print("\nGenerating Affine Cipher Key...")
    while True:
        a = random.randint(1, 25)  # 'a' must be coprime with 26
        if gcd(a, 26) == 1:
            break
    b = random.randint(0, 25)
    print(f"Generated Key: a = {a}, b = {b}")

def encrypt_affine():
    print("\nAffine Cipher Encryption")
    a = int(input("Enter key 'a' (must be coprime with 26): "))
    b = int(input("Enter key 'b': "))
    message = input("Enter the message to encrypt: ").upper()

    if gcd(a, 26) != 1:
        print("Error: 'a' must be coprime with 26.")
        return

    encrypted = "".join(
        chr(((a * (ord(char) - 65) + b) % 26) + 65) if char.isalpha() else char
        for char in message
    )
    print(f"Encrypted Message: {encrypted}")

def decrypt_affine():
    print("\nAffine Cipher Decryption")
    a = int(input("Enter key 'a' (must be coprime with 26): "))
    b = int(input("Enter key 'b': "))
    ciphertext = input("Enter the ciphertext to decrypt: ").upper()

    if gcd(a, 26) != 1:
        print("Error: 'a' must be coprime with 26.")
        return

    # Find modular inverse of 'a'
    a_inv = None
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break

    if a_inv is None:
        print("Error: Modular inverse of 'a' does not exist.")
        return

    decrypted = "".join(
        chr(((a_inv * ((ord(char) - 65) - b)) % 26) + 65) if char.isalpha() else char
        for char in ciphertext
    )
    print(f"Decrypted Message: {decrypted}")

def frequency_analysis():
    print("\nAnalyse Fréquentielle")
    print("1. Analyser un texte")
    print("2. Déchiffrer un texte")
    print("0. Retour au menu principal")
    
    choice = input("Sélectionnez une option (0-2): ")
    
    if choice == "0":
        return
    elif choice == "1":
        analyze_text()
    elif choice == "2":
        decrypt_with_frequency()
    else:
        print("Option invalide. Veuillez réessayer.")

def analyze_text():
    text = input("Entrez le texte à analyser : ").upper()
    freq = calculate_frequencies(text)
    print_frequency_analysis(freq)
    compare_with_french(freq)

def calculate_frequencies(text):
    freq = {}
    total = sum(1 for c in text if c.isalpha())
    
    for char in text:
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    # Convert to percentages
    if total > 0:
        freq = {k: (v/total)*100 for k, v in freq.items()}
    
    return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))

def print_frequency_analysis(freq):
    print("\nFréquences des lettres dans le texte :")
    for char, percentage in freq.items():
        print(f"{char}: {percentage:.2f}%")

def compare_with_french(freq):
    print("\nComparaison avec les fréquences en français :")
    print("Lettre | Texte (%) | Français (%)")
    print("-" * 35)
    
    for char in sorted(freq, key=freq.get, reverse=True):
        text_freq = freq.get(char, 0)
        french_freq = FRENCH_FREQUENCIES.get(char, 0)
        print(f"{char:^6} | {text_freq:8.2f} | {french_freq:8.2f}")

def decrypt_with_frequency(text=None):
    if text is None:
        text = input("Entrez le texte chiffré : ").upper()
    
    freq = calculate_frequencies(text)
    sorted_text_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    sorted_french = sorted(FRENCH_FREQUENCIES.items(), key=lambda x: x[1], reverse=True)
    
    # Create mapping based on frequency analysis
    mapping = {}
    for (text_char, _), (french_char, _) in zip(sorted_text_freq, sorted_french):
        mapping[text_char] = french_char
    
    # Decrypt the text
    decrypted = ''.join(mapping.get(c, c) for c in text)
    
    print("\nSuggestion de déchiffrement basée sur l'analyse fréquentielle :")
    print(f"Texte déchiffré : {decrypted}")
    print("\nNote : Cette suggestion est basée uniquement sur les fréquences des lettres.")
    print("Il peut être nécessaire d'ajuster manuellement pour obtenir un texte cohérent.")

def hill_cipher_menu():
    print("\nHill Cipher Menu")
    while True:
        print("1. Generate Key (2x2 matrix)")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_hill_key()
        elif choice == "2":
            encrypt_hill()
        elif choice == "3":
            decrypt_hill()
        else:
            print("Invalid choice. Please try again.")

def matrix_multiply(matrix, vector):
    return [
        sum(matrix[i][j] * vector[j] for j in range(len(vector))) % 26
        for i in range(len(matrix))
    ]

def matrix_determinant(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26

def matrix_inverse_mod26(matrix):
    det = matrix_determinant(matrix)
    # Find modular multiplicative inverse of determinant
    det_inv = None
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break
    
    if det_inv is None:
        return None
    
    # Calculate adjugate matrix
    adj = [
        [matrix[1][1], (-matrix[0][1]) % 26],
        [(-matrix[1][0]) % 26, matrix[0][0]]
    ]
    
    # Multiply adjugate by determinant inverse
    return [
        [(det_inv * adj[i][j]) % 26 for j in range(2)]
        for i in range(2)
    ]

def generate_hill_key():
    print("\nGenerating Hill Cipher Key (2x2 matrix)...")
    while True:
        # Generate random 2x2 matrix
        matrix = [
            [random.randint(0, 25), random.randint(0, 25)],
            [random.randint(0, 25), random.randint(0, 25)]
        ]
        
        # Check if matrix is invertible (determinant must be coprime with 26)
        det = matrix_determinant(matrix)
        if gcd(det, 26) == 1:
            print(f"\nGenerated Key Matrix:")
            print(f"[{matrix[0][0]} {matrix[0][1]}]")
            print(f"[{matrix[1][0]} {matrix[1][1]}]")
            return matrix
    
def encrypt_hill():
    print("\nHill Cipher Encryption")
    # Get the key matrix
    print("Enter the 2x2 key matrix elements (0-25):")
    matrix = []
    for i in range(2):
        row = []
        for j in range(2):
            val = int(input(f"Enter element [{i}][{j}]: "))
            row.append(val % 26)
        matrix.append(row)
    
    message = input("Enter the message to encrypt: ").upper()
    message = ''.join(c for c in message if c.isalpha())
    
    # Pad message if necessary
    if len(message) % 2 != 0:
        message += 'X'
    
    encrypted = ""
    for i in range(0, len(message), 2):
        # Convert pair of letters to numbers
        pair = [ord(message[i]) - 65, ord(message[i+1]) - 65]
        # Multiply matrix with pair
        result = matrix_multiply(matrix, pair)
        # Convert back to letters
        encrypted += chr(result[0] + 65) + chr(result[1] + 65)
    
    print(f"Encrypted message: {encrypted}")

def decrypt_hill():
    print("\nHill Cipher Decryption")
    # Get the key matrix
    print("Enter the 2x2 key matrix elements (0-25):")
    matrix = []
    for i in range(2):
        row = []
        for j in range(2):
            val = int(input(f"Enter element [{i}][{j}]: "))
            row.append(val % 26)
        matrix.append(row)
    
    # Calculate inverse matrix
    inverse = matrix_inverse_mod26(matrix)
    if inverse is None:
        print("Error: Matrix is not invertible modulo 26")
        return
    
    ciphertext = input("Enter the ciphertext to decrypt: ").upper()
    ciphertext = ''.join(c for c in ciphertext if c.isalpha())
    
    if len(ciphertext) % 2 != 0:
        print("Error: Ciphertext length must be even")
        return
    
    decrypted = ""
    for i in range(0, len(ciphertext), 2):
        # Convert pair of letters to numbers
        pair = [ord(ciphertext[i]) - 65, ord(ciphertext[i+1]) - 65]
        # Multiply inverse matrix with pair
        result = matrix_multiply(inverse, pair)
        # Convert back to letters
        decrypted += chr(result[0] + 65) + chr(result[1] + 65)
    
    print(f"Decrypted message: {decrypted}")

def create_playfair_matrix(key):
    # Initialiser la matrice avec le mot clé
    matrix = []
    used_chars = set()
    
    # D'abord ajouter les lettres du mot clé
    for char in key:
        if char.isalpha() and char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    
    # Puis ajouter le reste de l'alphabet (en remplaçant J par I)
    for char in string.ascii_uppercase:
        if char != 'J' and char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    
    # Convertir en matrice 5x5
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def display_playfair_matrix(matrix):
    for row in matrix:
        print(" ".join(row))

def find_positions(matrix, char1, char2):
    positions = []
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char1 or matrix[i][j] == char2:
                positions.append((i, j))
    return positions[0], positions[1]

def prepare_text(text):
    # Remplacer J par I et grouper par paires
    text = text.upper().replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:
            pairs.append(text[i] + 'X')
            break
        elif text[i] == text[i + 1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i] + text[i + 1])
            i += 2
    return pairs

def playfair_cipher_menu():
    print("\nChiffrement Playfair")
    while True:
        print("1. Générer la matrice clé")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        print("0. Retour au menu principal")
        
        choice = input("Sélectionnez une option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_playfair_matrix()
        elif choice == "2":
            encrypt_playfair()
        elif choice == "3":
            decrypt_playfair()
        else:
            print("Option invalide. Veuillez réessayer.")

def generate_playfair_matrix():
    print("\nGénération de la matrice Playfair")
    key = input("Entrez le mot clé (sans espaces): ").upper().replace('J', 'I')
    matrix = create_playfair_matrix(key)
    print("\nMatrice 5x5 générée:")
    display_playfair_matrix(matrix)
    return matrix

def encrypt_playfair():
    print("\nChiffrement Playfair")
    key = input("Entrez le mot clé (sans espaces): ").upper().replace('J', 'I')
    matrix = create_playfair_matrix(key)
    print("\nMatrice utilisée:")
    display_playfair_matrix(matrix)
    
    message = input("\nEntrez le message à chiffrer: ").upper().replace(" ", "")
    pairs = prepare_text(message)
    
    encrypted = ""
    for pair in pairs:
        p1, p2 = pair[0], pair[1]
        pos1, pos2 = find_positions(matrix, p1, p2)
        
        if pos1[0] == pos2[0]:  # Même ligne
            encrypted += matrix[pos1[0]][(pos1[1] + 1) % 5]
            encrypted += matrix[pos2[0]][(pos2[1] + 1) % 5]
        elif pos1[1] == pos2[1]:  # Même colonne
            encrypted += matrix[(pos1[0] + 1) % 5][pos1[1]]
            encrypted += matrix[(pos2[0] + 1) % 5][pos2[1]]
        else:  # Rectangle
            encrypted += matrix[pos1[0]][pos2[1]]
            encrypted += matrix[pos2[0]][pos1[1]]
    
    print(f"\nMessage chiffré: {encrypted}")
    return encrypted

def decrypt_playfair():
    print("\nDéchiffrement Playfair")
    key = input("Entrez le mot clé (sans espaces): ").upper().replace('J', 'I')
    matrix = create_playfair_matrix(key)
    print("\nMatrice utilisée:")
    display_playfair_matrix(matrix)
    
    ciphertext = input("\nEntrez le message chiffré: ").upper()
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    
    decrypted = ""
    for pair in pairs:
        p1, p2 = pair[0], pair[1]
        pos1, pos2 = find_positions(matrix, p1, p2)
        
        if pos1[0] == pos2[0]:  # Même ligne
            decrypted += matrix[pos1[0]][(pos1[1] - 1) % 5]
            decrypted += matrix[pos2[0]][(pos2[1] - 1) % 5]
        elif pos1[1] == pos2[1]:  # Même colonne
            decrypted += matrix[(pos1[0] - 1) % 5][pos1[1]]
            decrypted += matrix[(pos2[0] - 1) % 5][pos2[1]]
        else:  # Rectangle
            decrypted += matrix[pos1[0]][pos2[1]]
            decrypted += matrix[pos2[0]][pos1[1]]
    
    print(f"\nMessage déchiffré: {decrypted}")
    return decrypted

def vigenere_cipher_menu():
    print("\nVigenère Cipher Menu")
    while True:
        print("1. Generate Key")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_vigenere_key()
        elif choice == "2":
            encrypt_vigenere()
        elif choice == "3":
            decrypt_vigenere()
        else:
            print("Invalid choice. Please try again.")

def generate_vigenere_key():
    print("\nVigenère Cipher Key Generation")
    length = int(input("Enter desired key length: "))
    key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
    print(f"Generated key: {key}")
    return key

def encrypt_vigenere():
    print("\nVigenère Cipher Encryption")
    key = input("Enter the key: ").upper()
    message = input("Enter the message to encrypt: ").upper()
    message = ''.join(c for c in message if c.isalpha())
    
    # Extend key to message length
    full_key = (key * (len(message)//len(key) + 1))[:len(message)]
    
    encrypted = ""
    for i in range(len(message)):
        # Add the letters and wrap around if necessary
        shift = ord(full_key[i]) - 65
        char = chr((ord(message[i]) - 65 + shift) % 26 + 65)
        encrypted += char
    
    print(f"Encrypted message: {encrypted}")

def decrypt_vigenere():
    print("\nVigenère Cipher Decryption")
    key = input("Enter the key: ").upper()
    ciphertext = input("Enter the ciphertext to decrypt: ").upper()
    ciphertext = ''.join(c for c in ciphertext if c.isalpha())
    
    # Extend key to ciphertext length
    full_key = (key * (len(ciphertext)//len(key) + 1))[:len(ciphertext)]
    
    decrypted = ""
    for i in range(len(ciphertext)):
        # Subtract the key letters and wrap around if necessary
        shift = ord(full_key[i]) - 65
        char = chr((ord(ciphertext[i]) - 65 - shift) % 26 + 65)
        decrypted += char
    
    print(f"Decrypted message: {decrypted}")

def one_time_pad_menu():
    print("\nOne-Time Pad Menu")
    while True:
        print("1. Generate Random Key")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_otp_key()
        elif choice == "2":
            encrypt_otp()
        elif choice == "3":
            decrypt_otp()
        else:
            print("Invalid choice. Please try again.")

def generate_otp_key():
    print("\nOne-Time Pad Key Generation")
    length = int(input("Enter the length of the key (in bytes): "))
    key = get_random_bytes(length)
    print("\nGenerated key (in hexadecimal):")
    print(key.hex())
    return key

def encrypt_otp():
    print("\nOne-Time Pad Encryption")
    message = input("Enter the message to encrypt: ").encode()
    print("Enter the key (in hexadecimal):")
    try:
        key = bytes.fromhex(input())
        if len(key) < len(message):
            print("Error: Key must be at least as long as the message")
            return
        
        # XOR each byte of the message with the key
        encrypted = bytes(m ^ k for m, k in zip(message, key))
        print("\nEncrypted message (in hexadecimal):")
        print(encrypted.hex())
        
    except ValueError:
        print("Error: Invalid hexadecimal key")

def decrypt_otp():
    print("\nOne-Time Pad Decryption")
    print("Enter the encrypted message (in hexadecimal):")
    try:
        ciphertext = bytes.fromhex(input())
        print("Enter the key (in hexadecimal):")
        key = bytes.fromhex(input())
        
        if len(key) < len(ciphertext):
            print("Error: Key must be at least as long as the ciphertext")
            return
        
        # XOR each byte of the ciphertext with the key
        decrypted = bytes(c ^ k for c, k in zip(ciphertext, key))
        print("\nDecrypted message:")
        print(decrypted.decode())
        
    except ValueError as e:
        print(f"Error: {str(e)}")

def index_of_coincidence():
    print("\nIndice de Coïncidence (IC)")
    while True:
        print("\n1. Calculer l'IC d'un texte")
        print("2. Analyser la longueur probable de la clé Vigenère")
        print("3. Analyse multilangue (Français/Anglais)")
        print("0. Retour au menu principal")

        choice = input("\nSélectionnez une option (0-3): ")

        if choice == "0":
            break
        elif choice == "1":
            calculate_ic()
        elif choice == "2":
            analyze_vigenere_key_length()
        elif choice == "3":
            multilanguage_ic_analysis()
        else:
            print("Option invalide. Veuillez réessayer.")

def calculate_ic(text=None, display_details=True):
    """Calculate the Index of Coincidence for a given text."""
    if text is None:
        text = input("\nEntrez le texte à analyser : ").upper()
    
    # Clean and validate the text
    text = ''.join(c for c in text if c.isalpha())
    
    if len(text) < 2:
        if display_details:
            print("Le texte est trop court pour calculer l'IC.")
        return None
    
    # Count letter occurrences
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    
    # Calculate IC using the formula: Σ(ni(ni-1))/(N(N-1))
    n = len(text)
    sum_ni_ni_minus_1 = sum(count * (count - 1) for count in counts.values())
    ic = sum_ni_ni_minus_1 / (n * (n - 1))
    
    if display_details:
        print(f"\nRésultat de l'analyse:")
        print(f"Longueur du texte: {n} lettres")
        print(f"Nombre de caractères uniques: {len(counts)}")
        print(f"Indice de Coïncidence: {ic:.4f}")
        
        print("\nInterprétation:")
        if ic > 0.070:
            print("IC très élevé (>0.070): Texte potentiellement répétitif ou motif particulier")
        elif 0.065 <= ic <= 0.070:
            print("IC élevé (0.065-0.070): Probablement un chiffrement monoalphabétique")
        elif 0.060 <= ic < 0.065:
            print("IC normal-haut (0.060-0.065): Possiblement du texte français non chiffré")
        elif 0.045 <= ic < 0.060:
            print("IC normal (0.045-0.060): Texte en clair (français ou anglais)")
        elif 0.038 <= ic < 0.045:
            print("IC bas (0.038-0.045): Suggère un chiffrement polyalphabétique (comme Vigenère)")
        else:
            print("IC très bas (<0.038): Chiffrement complexe ou texte aléatoire")
    
    return ic

def analyze_vigenere_key_length():
    text = input("\nEntrez le texte chiffré à analyser : ").upper()
    text = ''.join(c for c in text if c.isalpha())
    
    if len(text) < 20:
        print("Le texte est trop court pour une analyse fiable.")
        return
    
    # Test key lengths from 2 to min(12, text_length/2)
    max_length = min(12, len(text) // 2)
    results = []
    
    print("\nAnalyse des longueurs de clé possibles:")
    for key_length in range(2, max_length + 1):
        # Split text into key_length sequences
        sequences = [''] * key_length
        for i, c in enumerate(text):
            sequences[i % key_length] += c
        
        # Calculate average IC for all sequences
        ics = []
        for seq in sequences:
            ic = calculate_ic(seq, display_details=False)
            if ic is not None:
                ics.append(ic)
        
        if ics:
            avg_ic = sum(ics) / len(ics)
            variance = sum((x - avg_ic) ** 2 for x in ics) / len(ics)
            
            # Score the likelihood based on IC value and variance
            score = (avg_ic - 0.038) * (1 - variance)
            results.append((key_length, avg_ic, variance, score))
    
    # Sort results by score
    results.sort(key=lambda x: x[3], reverse=True)
    
    print("\nRésultats triés par probabilité:")
    print("Longueur | IC moyen  | Variance  | Probabilité")
    print("-" * 45)
    
    for length, avg_ic, var, score in results:
        probability = "Très probable" if score > 0.015 else \
                     "Probable" if score > 0.010 else \
                     "Possible" if score > 0.005 else \
                     "Peu probable"
        print(f"{length:8d} | {avg_ic:.6f} | {var:.6f} | {probability}")
    
    # Print recommendation
    best_lengths = [r[0] for r in results if r[3] > 0.010]
    if best_lengths:
        print(f"\nRecommandation: Essayez d'abord une longueur de clé de {', '.join(map(str, best_lengths))}")
        print("Pour de meilleurs résultats, utilisez ces longueurs avec l'analyse des fréquences.")
    else:
        print("\nAucune longueur de clé ne semble particulièrement probable.")
        print("Le texte pourrait utiliser un autre type de chiffrement.")

def multilanguage_ic_analysis():
    text = input("\nEntrez le texte à analyser : ").upper()
    text = ''.join(c for c in text if c.isalpha())
    
    if len(text) < 20:
        print("Le texte est trop court pour une analyse fiable.")
        return
    
    # Calculate IC
    ic = calculate_ic(text, display_details=False)
    
    print("\nAnalyse multilangue:")
    print(f"Indice de Coïncidence: {ic:.4f}")
    
    # Expected IC values for different languages and encryption types
    expected_values = {
        "Français (texte clair)": (0.0778, "le plus élevé en raison de la fréquence des E"),
        "Anglais (texte clair)": (0.0667, "plus bas que le français"),
        "Substitution monoalphabétique (FR)": (0.0778, "identique au texte clair"),
        "Substitution monoalphabétique (EN)": (0.0667, "identique au texte clair"),
        "Vigenère (tous langages)": (0.0385, "environ"),
        "Texte aléatoire": (0.0385, "ou plus bas")
    }
    
    print("\nComparaison avec les valeurs attendues:")
    print("Type de texte              | IC attendu | Notes")
    print("-" * 65)
    
    for text_type, (expected_ic, note) in expected_values.items():
        difference = abs(ic - expected_ic)
        match = "✓" if difference < 0.005 else " "
        print(f"{text_type:25} | {expected_ic:.4f}   | {note} {match}")
    
    # Provide interpretation
    print("\nConclusion:")
    if 0.070 <= ic <= 0.085:
        print("Le texte ressemble le plus à du français non chiffré")
    elif 0.060 <= ic <= 0.070:
        print("Le texte ressemble le plus à de l'anglais non chiffré")
    elif 0.035 <= ic <= 0.045:
        print("Le texte semble être chiffré avec une méthode polyalphabétique (comme Vigenère)")
    else:
        print("Le texte pourrait être chiffré avec une méthode plus complexe ou être aléatoire")

def rc4_menu():
    """Menu for RC4 stream cipher operations"""
    print("\nChiffrement RC4 (Rivest Cipher 4)")
    while True:
        print("\nMenu:")
        print("1. Générer une clé")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        print("4. Informations sur RC4")
        print("0. Retour au menu principal")
        
        choice = input("\nSélectionnez une option (0-4) : ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_rc4_key()
        elif choice == "2":
            encrypt_rc4()
        elif choice == "3":
            decrypt_rc4()
        elif choice == "4":
            display_rc4_info()
        else:
            print("Option invalide. Veuillez réessayer.")

def generate_rc4_key():
    """Generate a random key for RC4 encryption"""
    print("\nGénération de clé RC4")
    print("Note: La longueur recommandée est de 16 octets (128 bits) ou plus.")
    length = int(input("Entrez la longueur de la clé en octets : "))
    
    if length < 1:
        print("Erreur : La longueur de la clé doit être positive.")
        return
    
    key = get_random_bytes(length)
    print("\nClé générée (hexadécimal) :")
    print(key.hex())
    print(f"\nLongueur de la clé : {length} octets ({length * 8} bits)")
    return key

def encrypt_rc4():
    """Encrypt a message using RC4"""
    print("\nChiffrement RC4")
    
    # Get the message
    message = input("Entrez le message à chiffrer : ").encode()
    
    # Get the key
    print("\nEntrez la clé (en hexadécimal) :")
    print("Exemple : 0123456789ABCDEF pour une clé de 16 octets")
    
    try:
        key = bytes.fromhex(input())
        if len(key) < 1:
            print("Erreur : La clé est vide.")
            return
        
        # Perform encryption
        encrypted = rc4_encrypt_decrypt(key, message)
        
        print("\nMessage chiffré (hexadécimal) :")
        print(encrypted.hex())
        
        # Display key info
        print(f"\nInformations :")
        print(f"- Longueur de la clé : {len(key)} octets ({len(key) * 8} bits)")
        print(f"- Longueur du message : {len(message)} octets")
        print(f"- Longueur du chiffré : {len(encrypted)} octets")
        
    except ValueError:
        print("Erreur : Clé hexadécimale invalide.")

def decrypt_rc4():
    """Decrypt a message using RC4"""
    print("\nDéchiffrement RC4")
    
    # Get the encrypted message
    print("Entrez le message chiffré (en hexadécimal) :")
    try:
        ciphertext = bytes.fromhex(input())
        
        # Get the key
        print("\nEntrez la clé (en hexadécimal) :")
        print("Exemple : 0123456789ABCDEF pour une clé de 16 octets")
        key = bytes.fromhex(input())
        
        if len(key) < 1:
            print("Erreur : La clé est vide.")
            return
        
        # Perform decryption
        decrypted = rc4_encrypt_decrypt(key, ciphertext)
        
        print("\nMessage déchiffré :")
        try:
            print(decrypted.decode('utf-8'))
        except UnicodeDecodeError:
            print("(Impossible d'afficher le message en texte - affichage hexadécimal)")
            print(decrypted.hex())
        
        # Display key info
        print(f"\nInformations :")
        print(f"- Longueur de la clé : {len(key)} octets ({len(key) * 8} bits)")
        print(f"- Longueur du message chiffré : {len(ciphertext)} octets")
        print(f"- Longueur du message déchiffré : {len(decrypted)} octets")
        
    except ValueError as e:
        print(f"Erreur : {str(e)}")

def display_rc4_info():
    """Display information about the RC4 algorithm"""
    print("\nInformations sur l'algorithme RC4")
    print("=" * 40)
    
    print("\nDescription :")
    print("RC4 (Rivest Cipher 4) est un algorithme de chiffrement à flot")
    print("développé par Ron Rivest pour RSA Security en 1987.")
    
    print("\nCaractéristiques :")
    print("- Chiffrement symétrique (même clé pour chiffrer et déchiffrer)")
    print("- Génère un flux de bits pseudo-aléatoire (keystream)")
    print("- Très simple et rapide à implémenter")
    print("- Longueur de clé variable (généralement 40-2048 bits)")
    
    print("\nFonctionnement :")
    print("1. Key Scheduling Algorithm (KSA) :")
    print("   - Initialise un tableau d'état de 256 octets")
    print("   - Permute ce tableau en fonction de la clé")
    
    print("\n2. Pseudo-Random Generation Algorithm (PRGA) :")
    print("   - Génère un octet de keystream à la fois")
    print("   - Utilise des opérations simples (addition et permutation)")
    
    print("\n3. Chiffrement :")
    print("   - XOR entre le message et le keystream")
    print("   - Même opération pour le chiffrement et le déchiffrement")
    
    print("\nSécurité :")
    print("Note: RC4 a des vulnérabilités connues. Pour un usage")
    print("cryptographique moderne, il est recommandé d'utiliser")
    print("des algorithmes plus récents comme AES-GCM ou ChaCha20.")
    
    input("\nAppuyez sur Entrée pour continuer...")

def aes_menu():
    print("\nChiffrement AES (Advanced Encryption Standard)")
    while True:
        print("\nMenu principal AES:")
        print("1. Générer une clé (128/192/256 bits)")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        print("4. Informations sur AES")
        print("0. Retour au menu principal")
        
        choice = input("\nSélectionnez une option (0-4) : ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_aes_key()
        elif choice == "2":
            encrypt_aes()
        elif choice == "3":
            decrypt_aes()
        elif choice == "4":
            display_aes_info()
        else:
            print("Option invalide. Veuillez réessayer.")

def display_aes_info():
    """Affiche des informations détaillées sur l'algorithme AES"""
    print("\nInformations sur l'algorithme AES (Advanced Encryption Standard)")
    print("=" * 60)
    
    print("\nDescription générale :")
    print("L'AES est un algorithme de chiffrement symétrique par blocs")
    print("standardisé par le NIST en 2001. Il est devenu le standard")
    print("mondial pour le chiffrement des données.")
    
    print("\nCaractéristiques principales :")
    print("- Taille de bloc : 128 bits (16 octets)")
    print("- Tailles de clé possibles :")
    print("  * 128 bits (10 tours)")
    print("  * 192 bits (12 tours)")
    print("  * 256 bits (14 tours)")
    
    print("\nOpérations de base :")
    print("1. SubBytes : Substitution non linéaire")
    print("2. ShiftRows : Permutation des lignes")
    print("3. MixColumns : Mélange des colonnes")
    print("4. AddRoundKey : Addition de la sous-clé")
    
    print("\nModes d'opération disponibles :")
    print("- CBC (Cipher Block Chaining)")
    print("- ECB (Electronic Codebook) - non recommandé")
    print("- CTR (Counter)")
    print("- GCM (Galois/Counter Mode)")
    
    print("\nSécurité :")
    print("- Résistant à la cryptanalyse linéaire et différentielle")
    print("- Aucune attaque pratique connue sur l'algorithme complet")
    print("- Recommandé pour les données sensibles (SECRET DÉFENSE)")
    
    input("\nAppuyez sur Entrée pour continuer...")

def generate_aes_key():
    """Génère une clé AES de la taille spécifiée"""
    print("\nGénération de clé AES")
    print("=====================")
    print("Choisissez la taille de la clé :")
    print("1. 128 bits (sécurité standard)")
    print("2. 192 bits (sécurité renforcée)")
    print("3. 256 bits (sécurité maximale)")
    
    key_sizes = {
        "1": 16,  # 128 bits
        "2": 24,  # 192 bits
        "3": 32   # 256 bits
    }
    
    while True:
        choice = input("\nVotre choix (1-3) : ")
        if choice in key_sizes:
            key = get_random_bytes(key_sizes[choice])
            bits = key_sizes[choice] * 8
            print(f"\nClé générée ({bits} bits) :")
            print(f"Format hexadécimal : {key.hex()}")
            print("\nConservez cette clé de manière sécurisée.")
            print("Elle sera nécessaire pour le déchiffrement.")
            return key
        else:
            print("Option invalide. Veuillez réessayer.")

def encrypt_aes():
    """Chiffre un message avec AES en mode CBC"""
    print("\nChiffrement AES")
    print("===============")
    
    try:
        message = input("Entrez le message à chiffrer : ").encode()
        print("\nEntrez la clé (format hexadécimal) :")
        print("Exemple : 00112233445566778899AABBCCDDEEFF (pour 128 bits)")
        key = bytes.fromhex(input())
        
        if len(key) not in (16, 24, 32):
            print("\nErreur : La clé doit faire 16, 24 ou 32 octets (128, 192 ou 256 bits)")
            return
            
        # Génération du vecteur d'initialisation (IV)
        iv = get_random_bytes(16)
        
        # Création de l'objet de chiffrement
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Chiffrement avec padding
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        
        # Concaténation de l'IV et du texte chiffré
        encrypted = iv + ciphertext
        
        print("\nMessage chiffré (format hexadécimal) :")
        print(encrypted.hex())
        print("\nNote : Les 32 premiers caractères représentent l'IV")
        
        # Affichage des informations techniques
        print(f"\nInformations techniques :")
        print(f"- Taille de la clé : {len(key) * 8} bits")
        print(f"- Taille de l'IV : {len(iv) * 8} bits")
        print(f"- Taille du message : {len(message)} octets")
        print(f"- Taille du chiffré : {len(encrypted)} octets")
        print(f"- Mode d'opération : CBC (Cipher Block Chaining)")
        
    except ValueError as e:
        print(f"\nErreur : {str(e)}")
        print("Vérifiez le format de la clé (hexadécimal uniquement)")

def decrypt_aes():
    """Déchiffre un message avec AES en mode CBC"""
    print("\nDéchiffrement AES")
    print("=================")
    
    try:
        print("Entrez le message chiffré (format hexadécimal) :")
        encrypted = bytes.fromhex(input())
        
        if len(encrypted) < 32:  # IV (16 bytes) + minimum un bloc (16 bytes)
            print("\nErreur : Message chiffré trop court")
            return
            
        print("\nEntrez la clé (format hexadécimal) :")
        print("Exemple : 00112233445566778899AABBCCDDEEFF (pour 128 bits)")
        key = bytes.fromhex(input())
        
        if len(key) not in (16, 24, 32):
            print("\nErreur : La clé doit faire 16, 24 ou 32 octets (128, 192 ou 256 bits)")
            return
        
        # Extraction de l'IV et du texte chiffré
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        
        # Création de l'objet de déchiffrement
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Déchiffrement et retrait du padding
        try:
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            print("\nMessage déchiffré :")
            print(decrypted.decode('utf-8'))
            
            # Affichage des informations techniques
            print(f"\nInformations techniques :")
            print(f"- Taille de la clé : {len(key) * 8} bits")
            print(f"- Taille de l'IV : {len(iv) * 8} bits")
            print(f"- Taille du message chiffré : {len(ciphertext)} octets")
            print(f"- Taille du message déchiffré : {len(decrypted)} octets")
            
        except ValueError as padding_error:
            print("\nErreur de padding : Le message n'a pas pu être déchiffré")
            print("Causes possibles :")
            print("- Clé incorrecte")
            print("- Message corrompu")
            print("- IV incorrect")
            
    except ValueError as e:
        print(f"\nErreur : {str(e)}")
        print("Vérifiez le format de la clé et du message (hexadécimal uniquement)")

def des_menu():
    print("\nChiffrement DES (Data Encryption Standard)")
    while True:
        print("\nMenu DES:")
        print("1. Générer une clé")
        print("2. Chiffrer un message")
        print("3. Déchiffrer un message")
        print("4. Informations sur DES")
        print("0. Retour au menu principal")
        
        choice = input("\nSélectionnez une option (0-4): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_des_key()
        elif choice == "2":
            encrypt_des()
        elif choice == "3":
            decrypt_des()
        elif choice == "4":
            display_des_info()
        else:
            print("Option invalide. Veuillez réessayer.")

def display_des_info():
    """Affiche des informations détaillées sur l'algorithme DES"""
    print("\nInformations sur DES (Data Encryption Standard)")
    print("=" * 50)
    
    print("\nDescription générale :")
    print("Le DES est un algorithme de chiffrement symétrique par blocs")
    print("développé par IBM et standardisé par le NIST en 1977.")
    
    print("\nCaractéristiques principales :")
    print("- Taille de bloc : 64 bits (8 octets)")
    print("- Taille de clé : 56 bits effectifs (8 octets dont 8 bits de parité)")
    print("- Structure de Feistel avec 16 tours")
    print("- Mode d'opération par défaut : CBC (Cipher Block Chaining)")
    
    print("\nOpérations de base :")
    print("1. Permutation initiale (IP)")
    print("2. 16 tours de chiffrement avec fonction de Feistel")
    print("3. Permutation finale (IP^-1)")
    
    print("\nSécurité :")
    print("Note : DES n'est plus considéré comme sûr pour les applications modernes")
    print("en raison de sa taille de clé limitée. Il est recommandé d'utiliser")
    print("AES ou Triple DES pour les applications nécessitant un niveau de")
    print("sécurité élevé.")
    
    input("\nAppuyez sur Entrée pour continuer...")

def generate_des_key():
    """Génère une clé DES avec vérification de la parité"""
    print("\nGénération de clé DES")
    print("=====================")

    # Génération de 56 bits aléatoires (7 octets)
    key_56 = get_random_bytes(7)
    key = bytearray()

    # Ajout des bits de parité pour obtenir une clé de 64 bits (8 octets)
    for byte in key_56:
        # Compte les bits à 1 dans l'octet
        count = bin(byte).count('1')
        # Ajoute un bit de parité pour avoir un nombre pair de 1
        parity_bit = 0 if count % 2 == 0 else 1
        # Combine l'octet original avec le bit de parité
        key.append((byte << 1) | parity_bit)

    print("\nClé générée (64 bits avec parité) :")
    print(f"Format hexadécimal : {key.hex()}")
    print(f"Longueur : 64 bits (56 bits effectifs + 8 bits de parité)")
    print("\nATTENTION : Conservez cette clé de manière sécurisée.")
    return bytes(key)

def encrypt_des():
    """Chiffre un message avec DES en mode CBC"""
    print("\nChiffrement DES")
    print("===============")
    
    try:
        # Récupération du message
        message = input("Entrez le message à chiffrer : ").encode()
        
        # Récupération de la clé
        print("\nEntrez la clé (8 octets en hexadécimal) :")
        print("Exemple : 0123456789ABCDEF")
        key = bytes.fromhex(input())
        
        if len(key) != 8:
            print("Erreur : La clé doit faire exactement 8 octets (64 bits)")
            return
            
        # Vérification de la parité des octets de la clé
        for byte in key:
            if bin(byte).count('1') % 2 != 0:
                print("Attention : Les bits de parité de la clé sont incorrects")
                if not input("Continuer quand même ? (o/N) : ").lower().startswith('o'):
                    return
                break

        # Génération du vecteur d'initialisation (IV)
        iv = get_random_bytes(8)
        
        # Création de l'objet de chiffrement en mode CBC
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Chiffrement avec padding PKCS7
        ciphertext = cipher.encrypt(pad(message, DES.block_size))
        
        # Concaténation de l'IV et du texte chiffré
        encrypted = iv + ciphertext
        
        print("\nMessage chiffré (format hexadécimal) :")
        print(encrypted.hex())
        print("\nNote : Les 16 premiers caractères représentent l'IV")
        
        # Affichage des informations techniques
        print(f"\nInformations techniques :")
        print(f"- Taille du message : {len(message)} octets")
        print(f"- Taille après padding : {len(message) + (DES.block_size - len(message) % DES.block_size) % DES.block_size} octets")
        print(f"- Mode d'opération : CBC (Cipher Block Chaining)")
        print(f"- IV : {iv.hex()}")
        
    except ValueError as e:
        print(f"\nErreur : {str(e)}")
        print("Vérifiez le format de la clé (hexadécimal uniquement)")
    except Exception as e:
        print(f"\nErreur inattendue : {str(e)}")

def decrypt_des():
    """Déchiffre un message chiffré avec DES en mode CBC"""
    print("\nDéchiffrement DES")
    print("=================")
    
    try:
        # Récupération du message chiffré
        print("Entrez le message chiffré (format hexadécimal) :")
        encrypted = bytes.fromhex(input())
        
        if len(encrypted) < 16:  # IV (8 octets) + minimum un bloc (8 octets)
            print("Erreur : Message chiffré invalide (trop court)")
            return
            
        # Récupération de la clé
        print("\nEntrez la clé (8 octets en hexadécimal) :")
        print("Exemple : 0123456789ABCDEF")
        key = bytes.fromhex(input())
        
        if len(key) != 8:
            print("Erreur : La clé doit faire exactement 8 octets (64 bits)")
            return
            
        # Vérification de la parité des octets de la clé
        for byte in key:
            if bin(byte).count('1') % 2 != 0:
                print("Attention : Les bits de parité de la clé sont incorrects")
                if not input("Continuer quand même ? (o/N) : ").lower().startswith('o'):
                    return
                break
        
        # Extraction de l'IV et du texte chiffré
        iv = encrypted[:8]
        ciphertext = encrypted[8:]
        
        # Création de l'objet de déchiffrement en mode CBC
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Déchiffrement et retrait du padding
        try:
            decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
            
            print("\nMessage déchiffré :")
            try:
                print(decrypted.decode('utf-8'))
            except UnicodeDecodeError:
                print("(Le message déchiffré n'est pas du texte UTF-8 valide)")
                print(f"Format hexadécimal : {decrypted.hex()}")
            
            # Affichage des informations techniques
            print(f"\nInformations techniques :")
            print(f"- Taille du message chiffré : {len(ciphertext)} octets")
            print(f"- Taille après déchiffrement : {len(decrypted)} octets")
            print(f"- Mode d'opération : CBC (Cipher Block Chaining)")
            print(f"- IV utilisé : {iv.hex()}")
            
        except ValueError as padding_error:
            print("\nErreur de padding : Le message n'a pas pu être déchiffré")
            print("Causes possibles :")
            print("- Clé incorrecte")
            print("- Message corrompu")
            print("- IV incorrect")
            
    except ValueError as e:
        print(f"\nErreur : {str(e)}")
        print("Vérifiez le format de la clé et du message (hexadécimal uniquement)")
    except Exception as e:
        print(f"\nErreur inattendue : {str(e)}")

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for r in range(s-1):
            x = (x * x) % n
            if x == 1: return False
            if x == n-1: break
        else: return False
    return True

def generate_prime(bits):
    """Generate a prime number of given bit length"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Make sure it's odd and of the right size
        if is_prime(n): return n

def elgamal_menu():
    print("\nElGamal Encryption System")
    while True:
        print("1. Generate Key Pair")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_elgamal_keys()
        elif choice == "2":
            encrypt_elgamal()
        elif choice == "3":
            decrypt_elgamal()
        else:
            print("Invalid choice. Please try again.")

def generate_elgamal_keys():
    print("\nElGamal Key Generation")
    print("Generating prime p...")
    bits = int(input("Enter number of bits for prime (e.g., 256): "))
    p = generate_prime(bits)
    
    # Find a generator g
    g = 2
    while pow(g, (p-1)//2, p) == 1:
        g += 1
    
    # Generate private key x
    x = random.randrange(2, p-1)
    
    # Calculate public key y = g^x mod p
    y = pow(g, x, p)
    
    print("\nPublic Key:")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"y = {y}")
    print("\nPrivate Key:")
    print(f"x = {x}")
    
    return (p, g, y), x

def encrypt_elgamal():
    print("\nElGamal Encryption")
    print("Enter public key parameters:")
    p = int(input("p = "))
    g = int(input("g = "))
    y = int(input("y = "))
    
    message = input("\nEnter the message to encrypt: ")
    
    # Convert message to number
    m = int.from_bytes(message.encode(), 'big')
    if m >= p:
        print("Error: Message too long for chosen prime")
        return
    
    # Generate ephemeral key k
    k = random.randrange(2, p-1)
    while gcd(k, p-1) != 1:
        k = random.randrange(2, p-1)
    
    # Calculate c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # Calculate c2 = m * y^k mod p
    c2 = (m * pow(y, k, p)) % p
    
    print("\nEncrypted message:")
    print(f"c1 = {c1}")
    print(f"c2 = {c2}")

def decrypt_elgamal():
    print("\nElGamal Decryption")
    print("Enter private key and parameters:")
    p = int(input("p = "))
    x = int(input("x = "))
    
    print("\nEnter encrypted message:")
    c1 = int(input("c1 = "))
    c2 = int(input("c2 = "))
    
    # Calculate s = c1^x mod p
    s = pow(c1, x, p)
    
    # Calculate s^(-1) mod p
    s_inv = pow(s, p-2, p)  # Fermat's little theorem for modular inverse
    
    # Calculate m = c2 * s^(-1) mod p
    m = (c2 * s_inv) % p
    
    # Convert number back to message
    try:
        decrypted = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
        print("\nDecrypted message:")
        print(decrypted)
    except Exception as e:
        print(f"Error decoding message: {str(e)}")

def block_cipher_modes_menu():
    print("\nBlock Cipher Modes Menu")
    while True:
        print("1. Generate AES Key")
        print("2. Encrypt using ECB Mode")
        print("3. Decrypt using ECB Mode")
        print("4. Encrypt using CBC Mode")
        print("5. Decrypt using CBC Mode")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-5): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_block_cipher_key()
        elif choice == "2":
            encrypt_ecb()
        elif choice == "3":
            decrypt_ecb()
        elif choice == "4":
            encrypt_cbc()
        elif choice == "5":
            decrypt_cbc()
        else:
            print("Invalid choice. Please try again.")

def generate_block_cipher_key():
    key = get_random_bytes(16)  # 128-bit key for AES
    print("\nGenerated AES key (hexadecimal):")
    print(key.hex())
    return key

def encrypt_ecb():
    print("\nAES ECB Mode Encryption")
    message = input("Enter the message to encrypt: ").encode()
    print("Enter the key (in hexadecimal):")
    try:
        key = bytes.fromhex(input())
        if len(key) != 16:
            print("Error: Key must be exactly 16 bytes (128 bits)")
            return
        
        # Create cipher object in ECB mode
        cipher = AES.new(key, AES.MODE_ECB)
        
        # Pad and encrypt
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        
        print("\nEncrypted message (hexadecimal):")
        print(ciphertext.hex())
        
        # Show weakness of ECB mode with repeated blocks
        if len(message) >= 32:
            print("\nWarning: ECB mode reveals patterns in the data!")
            blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
            for i, block1 in enumerate(blocks):
                for j, block2 in enumerate(blocks[i+1:], i+1):
                    if block1 == block2:
                        print(f"Found identical blocks at positions {i} and {j}")
        
    except ValueError as e:
        print(f"Error: {str(e)}")

def decrypt_ecb():
    print("\nAES ECB Mode Decryption")
    print("Enter the encrypted message (in hexadecimal):")
    try:
        ciphertext = bytes.fromhex(input())
        print("Enter the key (in hexadecimal):")
        key = bytes.fromhex(input())
        
        if len(key) != 16:
            print("Error: Key must be exactly 16 bytes (128 bits)")
            return
        
        # Create cipher object in ECB mode
        cipher = AES.new(key, AES.MODE_ECB)
        
        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        print("\nDecrypted message:")
        print(decrypted.decode())
        
    except ValueError as e:
        print(f"Error: {str(e)}")

def encrypt_cbc():
    print("\nAES CBC Mode Encryption")
    message = input("Enter the message to encrypt: ").encode()
    print("Enter the key (in hexadecimal):")
    try:
        key = bytes.fromhex(input())
        if len(key) != 16:
            print("Error: Key must be exactly 16 bytes (128 bits)")
            return
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Create cipher object in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        
        # Prepend IV to ciphertext
        encrypted = iv + ciphertext
        
        print("\nEncrypted message (hexadecimal):")
        print(encrypted.hex())
        print("\nNote : Les 32 premiers caractères représentent l'IV")
        
    except ValueError as e:
        print(f"Error: {str(e)}")

def decrypt_cbc():
    print("\nAES CBC Mode Decryption")
    print("Enter the encrypted message (in hexadecimal):")
    try:
        encrypted = bytes.fromhex(input())
        if len(encrypted) < 32:  # Need at least IV (16 bytes) + one block (16 bytes)
            print("Error: Invalid ciphertext (too short)")
            return
            
        print("Enter the key (in hexadecimal):")
        key = bytes.fromhex(input())
        if len(key) != 16:
            print("Error: Key must be exactly 16 bytes (128 bits)")
            return
        
        # Extract IV and ciphertext
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        
        # Create cipher object in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        print("\nDecrypted message:")
        print(decrypted.decode())
        
    except ValueError as e:
        print(f"Error: {str(e)}")

def rsa_menu():
    print("\nRSA Encryption System")
    while True:
        print("1. Generate Key Pair")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_rsa_keys()
        elif choice == "2":
            encrypt_rsa()
        elif choice == "3":
            decrypt_rsa()
        else:
            print("Invalid choice. Please try again.")

def extended_gcd(a, b):
    """Returns (gcd, x, y) such that a * x + b * y = gcd"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def generate_rsa_keys():
    print("\nRSA Key Generation")
    bits = int(input("Enter number of bits for prime numbers (e.g., 1024): "))
    
    # Generate two prime numbers
    print("Generating prime numbers p and q...")
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    
    # Calculate n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose public exponent e
    e = 65537  # Common choice for e
    
    # Calculate private exponent d
    # d * e ≡ 1 (mod phi)
    _, d, _ = extended_gcd(e, phi)
    d = d % phi
    if d < 0:
        d += phi
    
    print("\nPublic Key (n, e):")
    print(f"n = {n}")
    print(f"e = {e}")
    print("\nPrivate Key (n, d):")
    print(f"n = {n}")
    print(f"d = {d}")
    
    return (n, e), (n, d)

def encrypt_rsa():
    print("\nRSA Encryption")
    print("Enter public key:")
    n = int(input("n = "))
    e = int(input("e = "))
    
    message = input("\nEnter the message to encrypt: ")
    
    # Convert message to number
    m = int.from_bytes(message.encode(), 'big')
    if m >= n:
        print("Error: Message too long for chosen key size")
        return
    
    # Encrypt: c = m^e mod n
    c = pow(m, e, n)
    
    print("\nEncrypted message (decimal):")
    print(c)

def decrypt_rsa():
    print("\nRSA Decryption")
    print("Enter private key:")
    n = int(input("n = "))
    d = int(input("d = "))
    
    c = int(input("\nEnter the encrypted message (decimal): "))
    
    # Decrypt: m = c^d mod n
    m = pow(c, d, n)
    
    # Convert number back to message
    try:
        decrypted = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
        print("\nDecrypted message:")
        print(decrypted)
    except Exception as e:
        print(f"Error decoding message: {str(e)}")

def sha256_hash_function():
    print("\nSHA-256 Hash Function")
    while True:
        print("\n1. Hash a Message")
        print("2. Verify a Hash")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-2): ")
        
        if choice == "0":
            break
        elif choice == "1":
            hash_message()
        elif choice == "2":
            verify_hash()
        else:
            print("Invalid choice. Please try again.")

def hash_message():
    message = input("\nEnter the message to hash: ")
    
    # Create SHA-256 hash object
    hash_obj = SHA256.new()
    
    # Update with message bytes
    hash_obj.update(message.encode())
    
    # Get the hexadecimal representation of the hash
    hash_hex = hash_obj.hexdigest()
    
    print("\nSHA-256 hash (hexadecimal):")
    print(hash_hex)
    
    # Show some properties of the hash
    print("\nHash properties:")
    print(f"Length: {len(hash_hex)} hexadecimal characters = {len(hash_hex)*4} bits")
    print("Any change in the input will result in a completely different hash value")
    return hash_hex

def verify_hash():
    message = input("\nEnter the original message: ")
    hash_value = input("Enter the hash value to verify: ").lower()
    
    # Create SHA-256 hash object
    hash_obj = SHA256.new()
    
    # Update with message bytes
    hash_obj.update(message.encode())
    
    # Get the hexadecimal representation of the hash
    computed_hash = hash_obj.hexdigest()
    
    print("\nVerification result:")
    if hash_value == computed_hash:
        print("VALID: The hash matches the message")
        print("This means the message has not been modified")
    else:
        print("INVALID: The hash does not match the message")
        print("This means either the message or the hash is incorrect")
        print("\nExpected hash:", hash_value)
        print("Computed hash:", computed_hash)

def digital_signature_menu():
    print("\nDigital Signature Menu")
    while True:
        print("1. Generate RSA Key Pair")
        print("2. Sign a Message")
        print("3. Verify a Signature")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            generate_signing_keys()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        else:
            print("Invalid choice. Please try again.")

def generate_signing_keys():
    print("\nGenerating RSA Keys for Digital Signature")
    key = RSA.generate(2048)
    
    # Extract public and private components
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    
    print("\nPublic Key (save and share this):")
    print(public_key.decode())
    print("\nPrivate Key (keep this secret!):")
    print(private_key.decode())
    
    return public_key, private_key

def sign_message():
    print("\nDigital Signature - Signing")
    try:
        # Get private key
        private_key_pem = input("Enter your private key (PEM format):\n")
        private_key = RSA.import_key(private_key_pem)
        
        # Get message
        message = input("\nEnter the message to sign: ")
        
        # Create hash of message
        h = SHA256.new(message.encode())
        
        # Sign the hash
        signer = pkcs1_15.new(private_key)
        signature = signer.sign(h)
        
        print("\nSignature (in hexadecimal):")
        print(signature.hex())
        
        print("\nOriginal message:")
        print(message)
        
        return message, signature
        
    except Exception as e:
        print(f"Error during signing: {str(e)}")

def verify_signature():
    print("\nDigital Signature - Verification")
    try:
        # Get public key
        public_key_pem = input("Enter the signer's public key (PEM format):\n")
        public_key = RSA.import_key(public_key_pem)
        
        # Get original message
        message = input("\nEnter the original message: ")
        
        # Get signature
        signature_hex = input("Enter the signature (in hexadecimal): ")
        signature = bytes.fromhex(signature_hex)
        
        # Create hash of message
        h = SHA256.new(message.encode())
        
        # Verify the signature
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(h, signature)
            print("\nSUCCESS: The signature is valid!")
            print("This means:")
            print("1. The message was signed by the owner of the private key")
            print("2. The message has not been modified since it was signed")
            return True
        except ValueError:
            print("\nERROR: The signature is NOT valid!")
            print("This means either:")
            print("1. The message was modified after signing, or")
            print("2. The signature was not created by the owner of this public key")
            return False
            
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return False

def crypto_protocols_theory():
    print("\nCryptographic Protocols Theory")
    while True:
        print("\nSelect a protocol to learn about:")
        print("1. SSL/TLS (Secure Sockets Layer/Transport Layer Security)")
        print("2. SSH (Secure Shell)")
        print("3. PGP (Pretty Good Privacy)")
        print("0. Back to Main Menu")
        
        choice = input("Select an option (0-3): ")
        
        if choice == "0":
            break
        elif choice == "1":
            explain_ssl_tls()
        elif choice == "2":
            explain_ssh()
        elif choice == "3":
            explain_pgp()
        else:
            print("Invalid choice. Please try again.")

def explain_ssl_tls():
    print("\nSSL/TLS Protocol")
    print("================")
    print("Purpose: Secure communication over networks (especially HTTPS)")
    
    print("\nKey Components:")
    print("1. Digital Certificates (X.509)")
    print("2. Public Key Infrastructure (PKI)")
    print("3. Symmetric and Asymmetric Encryption")
    
    print("\nHandshake Process:")
    print("1. Client Hello (supported cipher suites)")
    print("2. Server Hello (chosen cipher suite)")
    print("3. Server Certificate")
    print("4. Key Exchange")
    print("5. Session Key Establishment")
    
    print("\nSecurity Features:")
    print("- Authentication (server and optionally client)")
    print("- Confidentiality (encryption)")
    print("- Integrity (message authentication codes)")
    print("- Perfect Forward Secrecy (in modern versions)")
    
    input("\nPress Enter to continue...")

def explain_ssh():
    print("\nSSH Protocol")
    print("===========")
    print("Purpose: Secure remote access to systems")
    
    print("\nKey Components:")
    print("1. Host Keys (server authentication)")
    print("2. User Authentication Methods:")
    print("   - Public Key")
    print("   - Password")
    print("   - Keyboard Interactive")
    
    print("\nConnection Process:")
    print("1. TCP Connection")
    print("2. Protocol Version Exchange")
    print("3. Key Exchange and Server Authentication")
    print("4. User Authentication")
    print("5. Channel Setup")
    
    print("\nSecurity Features:")
    print("- Server Authentication")
    print("- User Authentication")
    print("- Encrypted Communication")
    print("- Port Forwarding/Tunneling")
    
    input("\nPress Enter to continue...")

def explain_pgp():
    print("\nPGP (Pretty Good Privacy)")
    print("=========================")
    print("Purpose: Email and file encryption")
    
    print("\nKey Components:")
    print("1. Public/Private Key Pairs")
    print("2. Web of Trust (decentralized trust model)")
    print("3. Key Servers")
    
    print("\nOperations:")
    print("1. Digital Signatures")
    print("   - Hash message")
    print("   - Encrypt hash with private key")
    
    print("2. Encryption")
    print("   - Generate random session key")
    print("   - Encrypt message with session key")
    print("   - Encrypt session key with recipient's public key")
    
    print("\nAdvantages:")
    print("- End-to-end encryption")
    print("- No central authority needed")
    print("- Compatible with email")
    
    input("\nPress Enter to continue...")

def homomorphic_encryption_demo():
    print("\nHomomorphic Encryption (Conceptual Demo)")
    print("Suppose E(x) = x + 10 (toy example, not secure)")
    x = int(input("Enter x: "))
    y = int(input("Enter y: "))
    Ex = x + 10
    Ey = y + 10
    print(f"E(x) = {Ex}, E(y) = {Ey}")
    print(f"E(x) + E(y) = {Ex + Ey}")
    print(f"E(x+y) = {(x+y)+10}")
    print("Homomorphic property: E(x) + E(y) = E(x+y) + 10")

def shamir_secret_sharing_menu():
    print("\nShamir Secret Sharing (Conceptual Demo)")
    print("Secret is split into n shares, need k to reconstruct.")
    secret = int(input("Enter secret (integer): "))
    n = int(input("Enter number of shares: "))
    k = int(input("Enter threshold k: "))
    coeffs = [secret] + [random.randint(1, 100) for _ in range(k-1)]
    shares = []
    for i in range(1, n+1):
        accum = 0
        for power, coef in enumerate(coeffs):
            accum += coef * (i ** power)
        shares.append((i, accum))
    print("Shares:")
    for s in shares:
        print(s)
    print("To reconstruct, use any k shares and Lagrange interpolation (not implemented here for brevity).")

class HillCipher:
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    @staticmethod
    def matrix_mod_inverse(matrix: np.ndarray, modulus: int) -> np.ndarray:
        """Calculate the modular multiplicative inverse of a matrix."""
        det = int(round(np.linalg.det(matrix)))
        det_inverse = pow(det % modulus, -1, modulus)
        adjugate = np.round(det * np.linalg.inv(matrix)).astype(int)
        return (det_inverse * adjugate % modulus)
    
    @staticmethod
    def text_to_matrix(text: str, block_size: int) -> List[np.ndarray]:
        """Convert text to a list of numeric matrices."""
        # Pad text if necessary
        while len(text) % block_size != 0:
            text += 'X'
        
        # Convert to numeric values (A=0, B=1, etc.)
        numbers = [HillCipher.ALPHABET.index(c) for c in text.upper()]
        matrices = []
        
        for i in range(0, len(numbers), block_size):
            block = numbers[i:i + block_size]
            matrices.append(np.array(block))
            
        return matrices
    
    @staticmethod
    def matrix_to_text(matrices: List[np.ndarray]) -> str:
        """Convert numeric matrices back to text."""
        text = ''
        for matrix in matrices:
            for num in matrix:
                text += HillCipher.ALPHABET[int(num) % 26]
        return text

    @staticmethod
    def validate_key(key_matrix: np.ndarray) -> bool:
        """Validate if the key matrix is invertible modulo 26."""
        try:
            det = int(round(np.linalg.det(key_matrix)))
            return det != 0 and np.gcd(det % 26, 26) == 1
        except:
            return False
    
    @staticmethod
    def encrypt(text: str, key: List[List[int]]) -> Tuple[str, str]:
        """Encrypt text using Hill cipher: C = K × M mod 26"""
        key_matrix = np.array(key)
        block_size = len(key)
        
        if not HillCipher.validate_key(key_matrix):
            return "Erreur : La matrice clé n'est pas inversible modulo 26", ""
            
        # Convert text to matrices
        plain_matrices = HillCipher.text_to_matrix(text, block_size)
        
        # Encrypt each block: C = K × M mod 26
        cipher_matrices = []
        for block in plain_matrices:
            result = np.dot(key_matrix, block) % 26
            cipher_matrices.append(result)
            
        return "Chiffrement réussi", HillCipher.matrix_to_text(cipher_matrices)
    
    @staticmethod
    def decrypt(text: str, key: List[List[int]]) -> Tuple[str, str]:
        """Decrypt text using Hill cipher: M = K^(-1) × C mod 26"""
        key_matrix = np.array(key)
        block_size = len(key)
        
        if not HillCipher.validate_key(key_matrix):
            return "Erreur : La matrice clé n'est pas inversible modulo 26", ""
            
        # Calculate key inverse
        try:
            key_inverse = HillCipher.matrix_mod_inverse(key_matrix, 26)
        except:
            return "Erreur : Impossible de calculer l'inverse de la matrice clé", ""
            
        # Convert cipher text to matrices
        cipher_matrices = HillCipher.text_to_matrix(text, block_size)
        
        # Decrypt each block: M = K^(-1) × C mod 26
        plain_matrices = []
        for block in cipher_matrices:
            result = np.dot(key_inverse, block) % 26
            plain_matrices.append(result)
            
        return "Déchiffrement réussi", HillCipher.matrix_to_text(plain_matrices)

def hill_cipher():
    print("\nChiffre de Hill")
    print("1. Chiffrer")
    print("2. Déchiffrer")
    print("0. Retour au menu principal")
    
    choice = input("Sélectionnez une option (0-2): ")
    
    if choice == "0":
        return
        
    # Get key size
    size = int(input("Entrez la taille de la matrice clé (2 ou 3): "))
    if size not in [2, 3]:
        print("Taille de matrice non supportée. Utilisez 2 ou 3.")
        return
        
    # Get key matrix
    print(f"Entrez la matrice clé {size}x{size} (nombres entre 0 et 25, séparés par des espaces):")
    key = []
    for i in range(size):
        row = list(map(int, input(f"Ligne {i+1}: ").split()))
        if len(row) != size:
            print("Format de matrice invalide.")
            return
        key.append(row)
        
    if choice == "1":
        text = input("Entrez le texte à chiffrer : ").replace(" ", "").upper()
        message, result = HillCipher.encrypt(text, key)
        print(message)
        if result:
            print(f"Texte chiffré : {result}")
            
    elif choice == "2":
        text = input("Entrez le texte à déchiffrer : ").replace(" ", "").upper()
        message, result = HillCipher.decrypt(text, key)
        print(message)
        if result:
            print(f"Texte déchiffré : {result}")
    else:
        print("Option invalide. Veuillez réessayer.")

def rc4_ksa(key):
    """
    RC4 Key Scheduling Algorithm (KSA)
    Initializes and permutes the state array using the key.
    """
    S = list(range(256))  # Initialize state array with 0 to 255
    j = 0
    key_length = len(key)
    
    # Initial permutation of S
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
    
    return S

def rc4_prga(S):
    """
    RC4 Pseudo-Random Generation Algorithm (PRGA)
    Generates keystream bytes from the permuted state array.
    """
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values
        K = S[(S[i] + S[j]) % 256]  # Generate keystream byte
        yield K

def rc4_encrypt_decrypt(key, data):
    """
    RC4 encryption/decryption function (symmetric)
    The same operation is used for both encryption and decryption due to XOR properties.
    
    Parameters:
        key (bytes): The encryption/decryption key
        data (bytes): The data to encrypt/decrypt
        
    Returns:
        bytes: The encrypted/decrypted data
    """
    S = rc4_ksa(key)  # Initialize state using key
    keystream = rc4_prga(S)  # Generate keystream
    
    # XOR each byte of data with the keystream
    result = bytes(x ^ next(keystream) for x in data)
    
    return result

if __name__ == "__main__":
    main_menu()