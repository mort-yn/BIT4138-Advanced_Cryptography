class CryptographicPrimitives:
    # provide internal math layers including custom substitution and permutation configurations
    
    # 8-bit Substitution Box (Non-linear mapping for Confusion)
    S_BOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75
    ]
    
    # 32-bit Permutation Vector Mapping Index array (For Diffusion)
    P_BOX = [
        31, 24, 16, 8,  0,  27, 19, 11,
        3,  30, 22, 14, 6,  26, 18, 10,
        2,  29, 21, 13, 5,  25, 17, 9,
        1,  28, 20, 12, 4,  23, 15, 7
    ]

    @classmethod
    def apply_sbox(cls, value_32bit: int) -> int:
        # for splitting a 32bit integer into 4 bytes, processes them via S-Box, and recombine them
        b0 = (value_32bit >> 24) & 0x3F
        b1 = (value_32bit >> 16) & 0x3F
        b2 = (value_32bit >> 8) & 0x3F
        b3 = value_32bit & 0x3F
        
        sb0 = cls.S_BOX[b0]
        sb1 = cls.S_BOX[b1]
        sb2 = cls.S_BOX[b2]
        sb3 = cls.S_BOX[b3]
        
        return (sb0 << 24) | (sb1 << 16) | (sb2 << 8) | sb3

    @classmethod
    def apply_pbox(cls, value_32bit: int) -> int:
        # rearrange spatial bit positions inside a 32-bit integer according to the P-Box mapping
        permuted_value = 0
        for target_idx, source_idx in enumerate(cls.P_BOX):
            bit = (value_32bit >> source_idx) & 1
            permuted_value |= (bit << (31 - target_idx))
        return permuted_value


class AdvancedFeistelEngine:
    # core 64bit Feistel multiround simulation engine
    
    def __init__(self, total_rounds: int = 8):
        self.total_rounds = total_rounds
        self.block_size = 8  

    def _round_function_f(self, right_half: int, subkey: int) -> int:
        # non-linear cipher round execution mixing state inputs
        mixed_input = (right_half ^ subkey) & 0xFFFFFFFF
        substituted = CryptographicPrimitives.apply_sbox(mixed_input)
        return CryptographicPrimitives.apply_pbox(substituted)

    def _derive_round_subkeys(self, master_key: int) -> list:
        # derives a distinct subkey array configuration from the master key input
        subkeys = []
        for i in range(self.total_rounds):
            # dynamic circular shifts combined with a round constant to prevent symmetric keys
            shifted_key = ((master_key >> (i * 3)) | (master_key << (64 - (i * 3)))) & 0xFFFFFFFF
            subkeys.append(shifted_key ^ (i * 0x7F4A3C2B))
        return subkeys

    @staticmethod
    def apply_pkcs7_padding(data: bytes, block_size: int = 8) -> bytes:
        # applying the PKCS#7 standard block alignment padding
        padding_len = block_size - (len(data) % block_size)
        padding_bytes = bytes([padding_len] * padding_len)
        return data + padding_bytes

    @staticmethod
    def remove_pkcs7_padding(padded_data: bytes) -> bytes:
        # verifies and strips standard PKCS#7 padding values from the decrypted blocks
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > 8:
            raise ValueError("Cryptographic Failure: Invalid alignment formatting metadata identified.")
        for i in range(len(padded_data) - padding_len, len(padded_data)):
            if padded_data[i] != padding_len:
                raise ValueError("Cryptographic Failure: Structural padding byte mismatch occurred.")
        return padded_data[:-padding_len]

    def encrypt_block_64(self, block_bytes: bytes, master_key: int) -> bytes:
        # run encryption updates over a single 64bit block chunk
        value_64bit = int.from_bytes(block_bytes, byteorder='big')
        left = (value_64bit >> 32) & 0xFFFFFFFF
        right = value_64bit & 0xFFFFFFFF
        
        subkeys = self._derive_round_subkeys(master_key)
        
        for round_idx in range(self.total_rounds):
            next_left = right
            f_output = self._round_function_f(right, subkeys[round_idx])
            next_right = (left ^ f_output) & 0xFFFFFFFF
            left, right = next_left, next_right
            
        # final round swap reversal before recombining halves
        combined_output = (right << 32) | left
        return combined_output.to_bytes(8, byteorder='big')

    def decrypt_block_64(self, ciphertext_bytes: bytes, master_key: int) -> bytes:
        # runs decryption transformations by reversing subkey applications
        value_64bit = int.from_bytes(ciphertext_bytes, byteorder='big')
        left = (value_64bit >> 32) & 0xFFFFFFFF
        right = value_64bit & 0xFFFFFFFF
        
        subkeys = self._derive_round_subkeys(master_key)[::-1]  # Reverse subkeys
        
        for round_idx in range(self.total_rounds):
            next_left = right
            f_output = self._round_function_f(right, subkeys[round_idx])
            next_right = (left ^ f_output) & 0xFFFFFFFF
            left, right = next_left, next_right
            
        combined_output = (right << 32) | left
        return combined_output.to_bytes(8, byteorder='big')

    def encrypt_message(self, plaintext_string: str, master_key: int) -> bytes:
        # Processes long-form string messages through block division logic (ECB Mode layout)
        raw_bytes = plaintext_string.encode('utf-8')
        padded_bytes = self.apply_pkcs7_padding(raw_bytes, self.block_size)
        
        ciphertext_result = bytearray()
        for i in range(0, len(padded_bytes), self.block_size):
            block = padded_bytes[i:i + self.block_size]
            encrypted_block = self.encrypt_block_64(block, master_key)
            ciphertext_result.extend(encrypted_block)
            
        return bytes(ciphertext_result)

    def decrypt_message(self, ciphertext_bytes: bytes, master_key: int) -> str:
        # Decrypts and maps concatenated binary strings back to plain text strings
        decrypted_padded = bytearray()
        for i in range(0, len(ciphertext_bytes), self.block_size):
            block = ciphertext_bytes[i:i + self.block_size]
            decrypted_block = self.decrypt_block_64(block, master_key)
            decrypted_padded.extend(decrypted_block)
            
        clean_bytes = self.remove_pkcs7_padding(bytes(decrypted_padded))
        return clean_bytes.decode('utf-8')


