# Caesar Cipher Encryption Program

def encrypt(plaintext, shift):
    ciphertext = ""

    for char in plaintext:

        if char.isalpha():

            if char.isupper():
                ciphertext += chr(
                    (ord(char) - ord('A') + shift) % 26
                    + ord('A')
                )

            else:
                ciphertext += chr(
                    (ord(char) - ord('a') + shift) % 26
                    + ord('a')
                )

        else:
            ciphertext += char

    return ciphertext


# Main Program
plaintext = input("Enter the plaintext: ")
shift = int(input("Enter the shift value: "))

encrypted_text = encrypt(plaintext, shift)

print("\nEncrypted Text:", encrypted_text)



# Caesar Cipher Decryption Program

def decrypt(ciphertext, shift):
    plaintext = ""

    for char in ciphertext:

        if char.isalpha():

            if char.isupper():
                plaintext += chr(
                    (ord(char) - ord('A') - shift) % 26
                    + ord('A')
                )

            else:
                plaintext += chr(
                    (ord(char) - ord('a') - shift) % 26
                    + ord('a')
                )

        else:
            plaintext += char

    return plaintext


# Main Program
ciphertext = input("Enter the ciphertext: ")
shift = int(input("Enter the shift value used during encryption: "))

decrypted_text = decrypt(ciphertext, shift)

print("\nDecrypted Text:", decrypted_text)

