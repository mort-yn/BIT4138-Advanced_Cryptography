class LinearCongruentialGenerator:
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223, m: int = 2**32):
        self.state = seed
        self.a = a
        self.c = c
        self.m = m

    def next_bit(self) -> int:
        """Extracts a pseudorandom bit using the most significant bits of the LCG state."""
        self.state = (self.a * self.state + self.c) % self.m
        return (self.state >> 16) & 1

    def next_byte(self) -> int:
        """Assembles 8 generated bits into a functional byte."""
        byte_val = 0
        for _ in range(8):
            byte_val = (byte_val << 1) | self.next_bit()
        return byte_val


class StreamCipherEngine:
    @staticmethod
    def process_message(text: str, seed: int) -> bytes:
        lcg = LinearCongruentialGenerator(seed)
        output = []
        for char in text:
            # Generate a key byte for every character
            key_byte = lcg.next_byte()
            # Execute bitwise XOR operation
            output.append(ord(char) ^ key_byte)
        return bytes(output)

# Demonstration Validation
if __name__ == "__main__":
    message = "CRYPTOGRAPHY LAB"
    secret_seed = 987654321
    
    encrypted_bytes = StreamCipherEngine.process_message(message, secret_seed)
    # Convert encrypted non-printable elements to hex string format for presentation
    print(f"Encrypted Output (Hex): {encrypted_bytes.hex()}")
    
    # Decrypting utilizing identical seed state
    decrypted_bytes = StreamCipherEngine.process_message(encrypted_bytes.decode('latin-1'), secret_seed)
    print(f"Decrypted Result: {decrypted_bytes.decode('latin-1')}")