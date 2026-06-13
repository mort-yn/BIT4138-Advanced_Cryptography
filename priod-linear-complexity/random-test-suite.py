import math

class RandomnessTestingSuite:
    @staticmethod
    def run_frequency_test(binary_sequence: str) -> dict:
        """Performs statistical Monobit testing calculation loops[cite: 281, 296, 313]."""
        n = len(binary_sequence)
        if n == 0:
            return {"p_value": 0.0, "status": "Fail"}
        
        # Mapping bit counts to balance scale (+1 vs -1)
        s_n = sum(1 if b == '1' else -1 for b in binary_sequence)
        s_obs = abs(s_n) / math.sqrt(n)
        p_value = math.erfc(s_obs / math.sqrt(2))
        
        return {
            "sequence_length": n,
            "calculated_sum": s_n,
            "p_value": round(p_value, 6),
            "status": "Passes Randomness" if p_value >= 0.01 else "Fails Randomness"
        }

    @staticmethod
    def export_results_to_file(filename: str, sequence: str, analysis: dict):
        """Advanced Task: Persists testing metrics to an accessible storage path[cite: 327]."""
        with open(filename, "w") as f:
            f.write(f"--- SECURITY ANALYSIS LAB REPORT ---\n")
            f.write(f"Analyzed Binary Sequence: {sequence}\n")
            for k, v in analysis.items():
                f.write(f"{k.upper()}: {v}\n")

if __name__ == "__main__":
    print("\n--- STATISTICAL ANALYSIS RUN ---")
    sample_bits = "1101110010111011110001001010111001011101110"
    metrics = RandomnessTestingSuite.run_frequency_test(sample_bits)
    print(f"Frequency Test Outcome Summary[cite: 316]: {metrics}")
    RandomnessTestingSuite.export_results_to_file("cryptanalysis_report.txt", sample_bits, metrics)