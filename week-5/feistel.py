class FeistelCipherEngine:
    def __init__(self, rounds: int = 4):
        self.rounds = rounds

    def _round_f(self, right_half: int, subkey: int) -> int:
        """Substitution round logic causing non-linear state confusion[cite: 422, 448]."""
        return ((right_half >> 2) ^ (subkey * 0x9E3779B9)) & 0xFFFFFFFF

    def _generate_keys(self, master_key: int) -> list:
        return [(master_key ^ (i * 0x12345678)) & 0xFFFFFFFF for i in range(self.rounds)]

    def process_block(self, block_64: int, master_key: int, decrypt: bool = False) -> int:
        """Simulates full multi-round block encryption/decryption sequences[cite: 448, 477]."""
        left = (block_64 >> 32) & 0xFFFFFFFF
        right = block_64 & 0xFFFFFFFF
        subkeys = self._generate_keys(master_key)
        
        if decrypt:
            subkeys = subkeys[::-1]

        for i in range(self.rounds):
            next_left = right
            next_right = left ^ self._round_f(right, subkeys[i])
            left, right = next_left, next_right

        # Undo the final swap to correctly align components
        return (right << 32) | left

if __name__ == "__main__":
    print("\n--- FEISTEL SIMULATOR RUN ---")
    feistel = FeistelCipherEngine(rounds=4)
    master_key = 0xDEADC0DECAFEBABE
    
    original = 0xAAAAAAAABBBBBBBB
    cipher = feistel.process_block(original, master_key, decrypt=False)
    recovered = feistel.process_block(cipher, master_key, decrypt=True)
    
    # Avalanche Experiment: Flipping a single bit [cite: 471, 473]
    altered = 0xAAAAAAAABBBBBBBC
    cipher_altered = feistel.process_block(altered, master_key, decrypt=False)
    
    print(f"Original Block Data:        {hex(original)}")
    print(f"Encrypted Ciphertext Block: {hex(cipher)}")
    print(f"Decrypted Verification:     {hex(recovered)}")
    print(f"Altered Input Ciphertext:   {hex(cipher_altered)} (Avalanche Effect Demonstration) [cite: 449]")