import sys
import os

class CryptographicPrimitives:
    """Provides internal math layers including custom Substitution and Permutation configurations."""
    
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
        permuted_value = 0
        for target_idx, source_idx in enumerate(cls.P_BOX):
            bit = (value_32bit >> source_idx) & 1
            permuted_value |= (bit << (31 - target_idx))
        return permuted_value


class AdvancedFeistelEngine:
    # core 64bit Feistel multiround simulation engine with reporting integrations
    
    def __init__(self, total_rounds: int = 8):
        self.total_rounds = total_rounds
        self.block_size = 8  

    def _round_function_f(self, right_half: int, subkey: int) -> int:
        mixed_input = (right_half ^ subkey) & 0xFFFFFFFF
        substituted = CryptographicPrimitives.apply_sbox(mixed_input)
        return CryptographicPrimitives.apply_pbox(substituted)

    def _derive_round_subkeys(self, master_key: int) -> list:
        subkeys = []
        for i in range(self.total_rounds):
            shifted_key = ((master_key >> (i * 3)) | (master_key << (64 - (i * 3)))) & 0xFFFFFFFF
            subkeys.append(shifted_key ^ (i * 0x7F4A3C2B))
        return subkeys

    @staticmethod
    def apply_pkcs7_padding(data: bytes, block_size: int = 8) -> bytes:
        padding_len = block_size - (len(data) % block_size)
        padding_bytes = bytes([padding_len] * padding_len)
        return data + padding_bytes

    @staticmethod
    def remove_pkcs7_padding(padded_data: bytes) -> bytes:
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > 8:
            raise ValueError("Cryptographic Failure: Invalid alignment formatting metadata identified.")
        for i in range(len(padded_data) - padding_len, len(padded_data)):
            if padded_data[i] != padding_len:
                raise ValueError("Cryptographic Failure: Structural padding byte mismatch occurred.")
        return padded_data[:-padding_len]

    def encrypt_block_64(self, block_bytes: bytes, master_key: int) -> bytes:
        value_64bit = int.from_bytes(block_bytes, byteorder='big')
        left = (value_64bit >> 32) & 0xFFFFFFFF
        right = value_64bit & 0xFFFFFFFF
        
        subkeys = self._derive_round_subkeys(master_key)
        
        for round_idx in range(self.total_rounds):
            next_left = right
            f_output = self._round_function_f(right, subkeys[round_idx])
            next_right = (left ^ f_output) & 0xFFFFFFFF
            left, right = next_left, next_right
            
        combined_output = (right << 32) | left
        return combined_output.to_bytes(8, byteorder='big')

    def decrypt_block_64(self, ciphertext_bytes: bytes, master_key: int) -> bytes:
        value_64bit = int.from_bytes(ciphertext_bytes, byteorder='big')
        left = (value_64bit >> 32) & 0xFFFFFFFF
        right = value_64bit & 0xFFFFFFFF
        
        subkeys = self._derive_round_subkeys(master_key)[::-1]  
        
        for round_idx in range(self.total_rounds):
            next_left = right
            f_output = self._round_function_f(right, subkeys[round_idx])
            next_right = (left ^ f_output) & 0xFFFFFFFF
            left, right = next_left, next_right
            
        combined_output = (right << 32) | left
        return combined_output.to_bytes(8, byteorder='big')

    def encrypt_message(self, plaintext_string: str, master_key: int) -> tuple:
        """Processes long-form string messages and retains execution logs for reports."""
        raw_bytes = plaintext_string.encode('utf-8')
        padded_bytes = self.apply_pkcs7_padding(raw_bytes, self.block_size)
        
        logs = []
        ciphertext_result = bytearray()
        block_count = 0
        
        for i in range(0, len(padded_bytes), self.block_size):
            block = padded_bytes[i:i + self.block_size]
            encrypted_block = self.encrypt_block_64(block, master_key)
            ciphertext_result.extend(encrypted_block)
            
            logs.append({
                "block_num": block_count,
                "plain_hex": block.hex(),
                "cipher_hex": encrypted_block.hex()
            })
            block_count += 1
            
        return bytes(ciphertext_result), logs

    def decrypt_message(self, ciphertext_bytes: bytes, master_key: int) -> tuple:
        # decrypts messages and populates a sequence analysis log tracking layer
        logs = []
        decrypted_padded = bytearray()
        block_count = 0
        
        for i in range(0, len(ciphertext_bytes), self.block_size):
            block = ciphertext_bytes[i:i + self.block_size]
            decrypted_block = self.decrypt_block_64(block, master_key)
            decrypted_padded.extend(decrypted_block)
            
            logs.append({
                "block_num": block_count,
                "cipher_hex": block.hex(),
                "decrypted_hex": decrypted_block.hex()
            })
            block_count += 1
            
        clean_bytes = self.remove_pkcs7_padding(bytes(decrypted_padded))
        return clean_bytes.decode('utf-8'), logs


class CryptographicReportWriter:
    # Handles technical execution data consolidation into a cleanly formatted external Markdown file
    
    REPORT_FILE = "cryptographic_report.md"

    @classmethod
    def initialize_report(cls):
        # creates or resets the report file with header metadata structural frames
        with open(cls.REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("# BIT4138 Advanced Cryptography Framework Execution Report\n")
            f.write(f"Generated automated lab evaluation analysis tracking layers.\n")
            f.write("---\n\n")

    @classmethod
    def append_encryption_log(cls, plaintext: str, master_key: int, ciphertext_hex: str, logs: list):
        # appends technical data from encryption execution sequences
        with open(cls.REPORT_FILE, "a", encoding="utf-8") as f:
            f.write("## 1. Encryption Transaction Operations Log\n")
            f.write(f"* **Input Raw String:** `{plaintext}`\n")
            f.write(f"* **Master Configuration Key:** `0x{master_key:016X}`\n")
            f.write(f"* **Aggregated Ciphertext Output:** `{ciphertext_hex}`\n\n")
            f.write("### Matrix Block Segmentation Profiles\n")
            f.write("| Block Sequence Index | Plaintext Segment Block (Hex) | Resulting Ciphertext Block (Hex) |\n")
            f.write("|---|---|---|\n")
            for log in logs:
                f.write(f"| Block #{log['block_num']} | `{log['plain_hex']}` | `{log['cipher_hex']}` |\n")
            f.write("\n---\n\n")

    @classmethod
    def append_decryption_log(cls, ciphertext_hex: str, master_key: int, recovered_text: str, logs: list):
        # appends analytical validation tracking profiles from decryption execution runs
        with open(cls.REPORT_FILE, "a", encoding="utf-8") as f:
            f.write("## 2. Decryption Verification Operations Log\n")
            f.write(f"* **Target Ciphertext Payload Input:** `{ciphertext_hex}`\n")
            f.write(f"* **Verification Master Key Scheme:** `0x{master_key:016X}`\n")
            f.write(f"* **Successfully Recovered Plain Text String:** `{recovered_text}`\n\n")
            f.write("### Block Parsing Verification Matrices\n")
            f.write("| Block Sequence Index | Target Ciphertext Input Block (Hex) | Decrypted Output Block (Hex) |\n")
            f.write("|---|---|---|\n")
            for log in logs:
                f.write(f"| Block #{log['block_num']} | `{log['cipher_hex']}` | `{log['decrypted_hex']}` |\n")
            f.write("\n---\n\n")

    @classmethod
    def append_avalanche_log(cls, input_orig: str, input_alt: str, c1_hex: str, c2_hex: str, metrics: dict):
        # appends statistical validation parameters resulting from active avalanche experiments
        with open(cls.REPORT_FILE, "a", encoding="utf-8") as f:
            f.write("## 3. Diffusion Evaluation: Avalanche Effect Experiment\n")
            f.write(f"* **Baseline Plaintext Vector ($P_1$):** `{input_orig}`\n")
            f.write(f"* **Altered Plaintext Vector ($P_2$):** `{input_alt}` (Single bit modified configuration)\n")
            f.write(f"* **Baseline Ciphertext Hex Output ($C_1$):** `{c1_hex}`\n")
            f.write(f"* **Altered Ciphertext Hex Output ($C_2$):** `{c2_hex}`\n\n")
            f.write("### Statistical Measurement Performance Indicators\n")
            f.write(f"| Evaluation Parameter Metric | Tracked Output Value Measurements |\n")
            f.write(f"|---|---||\n")
            f.write(f"| Total Aggregated Block Sizing Bit Constraints | {metrics['total_bits']} bits |\n")
            f.write(f"| Divergent Flipped Bit Intercept Count (Hamming Distance) | {metrics['flipped_bits']} bits |\n")
            f.write(f"| Evaluated Diffusion Cascade Density Ratio | **{metrics['ratio']:.2f}%** |\n")
            f.write(f"| Security Threshold Framework Status Check | **{metrics['status']}** |\n")
            f.write("\n---")


class CryptanalysisLabSuite:
    # contains verification utilities for statistical randomness metrics testing
    
    @staticmethod
    def count_bit_differences(bytes_a: bytes, bytes_b: bytes) -> int:
        diff_count = 0
        for b1, b2 in zip(bytes_a, bytes_b):
            xor_result = b1 ^ b2
            diff_count += bin(xor_result).count('1')
        return diff_count

    @classmethod
    def execute_avalanche_experiment(cls, cipher_engine: AdvancedFeistelEngine, text_input: str, master_key: int):
        print("\n=== AVALANCHE EFFECT EXPERIMENT METRICS ===")
        print(f"Original Text Input:  '{text_input}'")
        
        altered_char = chr(ord(text_input[0]) ^ 1)
        altered_input = altered_char + text_input[1:]
        print(f"Altered Input String: '{altered_input}' (Single-bit discrepancy injected)")
        
        c1, _ = cipher_engine.encrypt_message(text_input, master_key)
        c2, _ = cipher_engine.encrypt_message(altered_input, master_key)
        
        print(f"Ciphertext 1 (Hex):   {c1.hex()}")
        print(f"Ciphertext 2 (Hex):   {c2.hex()}")
        
        total_bits = len(c1) * 8
        flipped_bits = cls.count_bit_differences(c1, c2)
        avalanche_ratio = (flipped_bits / total_bits) * 100
        
        status_msg = "Robust Diffusion Achieved" if 45 <= avalanche_ratio <= 55 else "Weak Linear Structural Profiling"
        
        print(f"Total Evaluated Block Bits: {total_bits}")
        print(f"Observed Flipped Bit Count:  {flipped_bits}")
        print(f"Calculated Avalanche Ratio:  {avalanche_ratio:.2f}%")
        print(f"Status Check:  {status_msg}")
        
        metrics = {
            "total_bits": total_bits,
            "flipped_bits": flipped_bits,
            "ratio": avalanche_ratio,
            "status": status_msg
        }
        
        CryptographicReportWriter.append_avalanche_log(text_input, altered_input, c1.hex(), c2.hex(), metrics)
        print(f"\n[System Alert]: Avalanche data values appended to report file.")


def display_interactive_menu():
    engine = AdvancedFeistelEngine(total_rounds=8)
    master_key = 0xabcdef1234567890 
    
    # Initialize/Reset the markdown file header setup at startup execution
    CryptographicReportWriter.initialize_report()
    
    while True:
        print("\n" + "="*50)
        print("    ADVANCED CRYPTOGRAPHIC SYSTEM & REPORT GENERATOR   ")
        print("="*50)
        print("1. Encrypt Plaintext Message")
        print("2. Decrypt Ciphertext Payload")
        print("3. Execute Automated Avalanche Analysis Experiment")
        print("4. Exit Terminal Interface")
        print("="*50)
        
        choice = input("Select an option (1-4): ").strip()
        
        if choice == '1':
            msg = input("Enter plain string text to encrypt: ")
            if not msg:
                print("Error: Input string cannot be empty.")
                continue
            cipher_output, enc_logs = engine.encrypt_message(msg, master_key)
            cipher_hex = cipher_output.hex()
            
            print(f"\n--- CONSOLE ENCRYPTION OUTPUT DISPLAY ---")
            print(f"Resulting Output Encrypted Hex String: {cipher_hex}")
            print(f"Total Segments Parsed: {len(enc_logs)} blocks.")
            
            # Log execution events into markdown schema files
            CryptographicReportWriter.append_encryption_log(msg, master_key, cipher_hex, enc_logs)
            print("[System Alert]: Transaction log compiled inside 'cryptographic_report.md'.")
            
        elif choice == '2':
            hex_str = input("Enter hex-encoded ciphertext to decode: ").strip()
            try:
                cipher_bytes = bytes.fromhex(hex_str)
                decrypted_msg, dec_logs = engine.decrypt_message(cipher_bytes, master_key)
                
                print(f"\n--- CONSOLE DECRYPTION OUTPUT DISPLAY ---")
                print(f"Recovered Clean Decrypted String Text: {decrypted_msg}")
                
                # Log execution events into markdown schema files
                CryptographicReportWriter.append_decryption_log(hex_str, master_key, decrypted_msg, dec_logs)
                print("[System Alert]: Transaction verification data logged inside 'cryptographic_report.md'.")
            except Exception as e:
                print(f"Execution Error: Processing error encountered during translation. Details: {e}")
                
        elif choice == '3':
            sample_text = "Cryptography"
            CryptanalysisLabSuite.execute_avalanche_experiment(engine, sample_text, master_key)
            
        elif choice == '4':
            print(f"\nShutting down terminal session... Final report written to '{os.path.abspath(CryptographicReportWriter.REPORT_FILE)}'.\nGoodbye.")
            sys.exit(0)
            
        else:
            print("Selection error. Please input a numerical value from 1 to 4.")


if __name__ == "__main__":
    display_interactive_menu()