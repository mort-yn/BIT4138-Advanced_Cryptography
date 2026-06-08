# Vigenère Cipher Encryption

def encrypt_vigenere(plaintext, key):
    ciphertext = ""
    key = key.upper()
    key_index = 0

    for char in plaintext:

        if char.isalpha():

            shift = ord(key[key_index % len(key)]) - ord('A')

            if char.isupper():
                encrypted_char = chr(
                    (ord(char) - ord('A') + shift) % 26
                    + ord('A')
                )
            else:
                encrypted_char = chr(
                    (ord(char) - ord('a') + shift) % 26
                    + ord('a')
                )

            ciphertext += encrypted_char
            key_index += 1

        else:
            ciphertext += char

    return ciphertext


# Main Program
plaintext = input("Enter plaintext: ")
key = input("Enter key: ")

ciphertext = encrypt_vigenere(plaintext, key)

print("\nCiphertext:", ciphertext)


## Vigenère Cipher Decryption

def decrypt_vigenere(ciphertext, key):
    plaintext = ""
    key = key.upper()
    key_index = 0

    for char in ciphertext:

        if char.isalpha():

            shift = ord(key[key_index % len(key)]) - ord('A')

            if char.isupper():
                decrypted_char = chr(
                    (ord(char) - ord('A') - shift) % 26
                    + ord('A')
                )
            else:
                decrypted_char = chr(
                    (ord(char) - ord('a') - shift) % 26
                    + ord('a')
                )

            plaintext += decrypted_char
            key_index += 1

        else:
            plaintext += char

    return plaintext


# Main Program
ciphertext = input("Enter ciphertext: ")
key = input("Enter key: ")

plaintext = decrypt_vigenere(ciphertext, key)

print("\nPlaintext:", plaintext)