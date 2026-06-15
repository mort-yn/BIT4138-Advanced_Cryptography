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


