// EXACT NIST reference implementation - no modifications

pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 48;
pub const N: usize = 256;
pub const Q: usize = 8380417; // ML-DSA uses different modulus than ML-KEM
pub const D: usize = 13;
pub const ROOT_OF_UNITY: usize = 1753;

// ML-DSA-65 specific constants
pub const K: usize = 6; // ML-DSA uses different K than ML-KEM
pub const L: usize = 5;
pub const ETA: usize = 4;
pub const TAU: usize = 49;
pub const BETA: usize = 196;
pub const GAMMA1: usize = 524288; // (1 << 19)
pub const GAMMA2: usize = 261888; // ((Q-1)/32)
pub const OMEGA: usize = 55;

// Polynomial packing constants
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const POLYZ_PACKEDBYTES: usize = 640; // For GAMMA1 == (1 << 19)
pub const POLYW1_PACKEDBYTES: usize = 128; // For GAMMA2 == (Q-1)/32
pub const POLYETA_PACKEDBYTES: usize = 128; // For ETA == 4

// Signature-specific constants
pub const SIGNATUREBYTES: usize = 3293; // CRYPTO_BYTES for ML-DSA-65
pub const PUBLICKEYBYTES: usize = 1952; // CRYPTO_PUBLICKEYBYTES for ML-DSA-65
pub const SECRETKEYBYTES: usize = 4016; // CRYPTO_SECRETKEYBYTES for ML-DSA-65

// Crypto API constants (aliases for compatibility)
pub const CRYPTO_BYTES: usize = SIGNATUREBYTES;
pub const CRYPTO_PUBLICKEYBYTES: usize = PUBLICKEYBYTES;
pub const CRYPTO_SECRETKEYBYTES: usize = SECRETKEYBYTES;

// Polynomial constants
pub const POLYBYTES: usize = 416;
pub const POLYVECBYTES: usize = K * POLYBYTES;
pub const POLYCOMPRESSEDBYTES: usize = 576;
