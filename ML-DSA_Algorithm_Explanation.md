# ML-DSA (Dilithium) — Step-by-Step Algorithm Explanation

Analyzed codebase: NIST-ML-DSA/Reference_Implementation/crypto_sign/dilithium5-R
Detected DILITHIUM_MODE = 5
This document explains how the reference C code implements ML-DSA (Dilithium), with detailed arithmetic and pointers to concrete functions and files.

---

## 0) Parameters, rings, and notation

• Ring Rq = Z_q[x] / (x^N + 1).
  - N = 256.
  - q = 8380417 (23-bit prime).
• Vector shapes: polyvecl has length L = 7; polyveck has length K = 8.
• Distributions and bounds:
  - ETA = 2 for short secrets s1 in Rq^L and s2 in Rq^K.
  - GAMMA1 ≈ (1 << 19) for the y vector (wide).
  - GAMMA2 = ((Q-1)/32) governs decomposition and rounding.
  - BETA = 120 used in signing rejection checks.
  - TAU = 60 non-zeros in the sparse challenge c.
  - OMEGA = 75 maximum total hint weight.
• Domains: standard (coeffs in [0, q)), Montgomery (scaled by R = 2^32), and NTT domain.
  - montgomery_reduce in reduce.c maps a 64-bit product to Montgomery domain modulo q.
  - ntt and invntt_tomont in ntt.c implement forward and inverse negacyclic NTT of size N.

Files to keep open: sign.c (top-level), poly.c and polyvec.c (poly arithmetic and vectors), ntt.c and reduce.c (arithmetic core), rounding.c (rounding, decompose, hints), packing.c (serialization), symmetric.h and fips202.c (SHAKE).

---

## 1) Matrix expansion A from rho
Function: polyvec_matrix_expand in polyvec.c
For each row i in 0..K-1 and column j in 0..L-1, call poly_uniform(rho, i<<8 | j) to fill a_ij in Rq by rejection sampling from SHAKE128. Coefficients are in [0, q).

---

## 2) Key generation
API: crypto_sign_keypair in sign.c

2.1 Seeds
• randombytes fills a 32-byte seed, then SHAKE256 expands to rho, rhoprime, key (each 32 bytes).

2.2 Sample short secrets s1 in Rq^L and s2 in Rq^K
• polyvecl_uniform_eta and polyveck_uniform_eta with nonce increment. Output coefficients are centered small integers in [-ETA, ETA].

2.3 Compute t = A*s1 + s2
• Expand A from rho using polyvec_matrix_expand.
• Move s1 to NTT domain: polyvecl_ntt.
• Compute per row i the pointwise NTT product and accumulate: t_i_hat = sum_j a_ij_hat * s1_j_hat (Montgomery products).
• Inverse NTT: polyveck_invntt_tomont; then polyveck_reduce; finally add s2.

2.4 Split t into high and low and pack keys
• power2round in rounding.c: for each coefficient a, find a1 and a0 with base 2^D (D = 13).
• Public key pk = (rho, t1). Secret key sk = (rho, tr = CRH(pk), key, t0, s1, s2).
• Packing via pack_pk and pack_sk in packing.c.

---

## 3) Signing
API: crypto_sign_signature in sign.c
This directory enables randomized signing; in deterministic mode rhoprime is CRH(key || mu).

3.1 Unpack secrets and compute mu
• unpack_sk to get rho, tr, key, t0, s1, s2. Compute mu = CRH(tr || m).

3.2 Choose per-signature randomness rhoprime
• randomized mode uses randombytes; deterministic uses CRH(key || mu).

3.3 Sample y in Rq^L and compute w = A*y
• polyvecl_uniform_gamma1 samples y with coefficients in [-(GAMMA1-1), GAMMA1].
• NTT y, multiply A*y in NTT+Montgomery, inverse NTT, reduce.
• Decompose w into high w1 and low w0 via polyveck_decompose; low in (-GAMMA2, GAMMA2], high is quotient by ALPHA = 2*GAMMA2.

3.4 Challenge c = H(mu || pack_w1(w1))
• poly_challenge turns 32 bytes into a sparse polynomial with TAU non-zeros at ±1. Signs come from a 64-bit mask; positions sampled without replacement from SHAKE output.

3.5 Form z = y + c*s1 and check its infinity-norm
• Multiply c with s1 in NTT domain, inverse NTT, add y, reduce. Reject if any coefficient of z has magnitude at least GAMMA1 - BETA.

3.6 Check that w0 - c*s2 stays within GAMMA2 - BETA
• Compute c*s2, inverse NTT, subtract from w0, reduce. Reject if any coefficient has magnitude at least GAMMA2 - BETA.

3.7 Build hint vector h using t0
• Compute h_temp = c*t0 (NTT multiply, inverse NTT) and add to w0.
• polyveck_make_hint decides per coefficient whether a carry into the high bits would occur. Sum of ones must be at most OMEGA; otherwise reject and resample y.

3.8 Output signature
• pack_sig packs c (32 bytes), z (L polys), and h (sparse).

---

## 4) Verification
API: crypto_sign_verify in sign.c

4.1 Unpack and prelim checks
• unpack_pk and unpack_sig. Check sig length and that z passes the GAMMA1 - BETA bound.

4.2 Recompute mu and challenge c
• tr = CRH(pk). mu = CRH(tr || m). Rebuild c with poly_challenge.

4.3 Recompute w' = A*z - c*t1
• Expand A from rho. NTT z. Multiply A*z in NTT+Montgomery. Subtract c*t1 in NTT domain. Inverse NTT and reduce.

4.4 Use hints to recover w1 and rehash
• Decompose w' to (w1, w0) and then apply hints with polyveck_use_hint.
• Pack w1 via polyveck_pack_w1 and hash with mu to compare with c. Accept iff equal and all bounds hold.

---

## 5) Arithmetic details

5.1 NTT and inverse NTT
• ntt in ntt.c performs layered butterflies with twiddle factors zetas. Each butterfly computes t = montgomery_reduce(v * zeta), then u' = barrett_reduce(u + t) and v' = barrett_reduce(u - t).
• invntt_tomont scales by a fixed Montgomery constant so output remains in Montgomery domain; later caddq/freeze moves to standard reps.

5.2 Montgomery reduction in reduce.c
• Given 64-bit a, compute t = (a * qinv) mod 2^32, r = (a + t*q) >> 32, then conditionally subtract q to land in (-q, q).

5.3 Rounding, decomposition, hints in rounding.c
• power2round: split a into a1 and a0 with base 2^D so that a = a1*2^D + a0 with a0 in (-2^(D-1), 2^(D-1)].
• decompose: split a against ALPHA = 2*GAMMA2; a1 is a coarse quotient from a/ALPHA reduced to a small set; a0 is centered remainder in (-GAMMA2, GAMMA2].
• make_hint/use_hint: signal and consume whether adding or subtracting low parts would change the high part during verification reconstruction.

5.4 Challenge polynomial in poly.c
• poly_challenge constructs a sparse c with exactly TAU non-zero coefficients at positions chosen without replacement; signs from a 64-bit mask from SHAKE256(mu || pack_w1(w1)).

5.5 Rejection conditions during signing
• Norm of z strictly less than GAMMA1 - BETA.
• Norm of w0 - c*s2 strictly less than GAMMA2 - BETA.
• Hint weight at most OMEGA.

---

## 6) Serialization summary
• Public key pk = (rho, t1).
• Secret key sk = (rho, tr, key, t0, s1, s2).
• Signature sig = (c, z, h) where h is sparse with total ones at most OMEGA.
• packing and unpacking live in packing.c, including validation of h indices and weight bounds.

---

## 7) Mode-dependent parameters (typical)
The code contains three NIST modes (2, 3, 5). Broadly:
• Mode 2: (K, L) = (4, 4), ETA 2, GAMMA1 2^17, GAMMA2 (q - 1)/32, BETA 78, TAU 39, OMEGA 80.
• Mode 3: (K, L) = (6, 5), ETA 4, GAMMA1 2^19, GAMMA2 (q - 1)/88, BETA 100, TAU 49, OMEGA 55.
• Mode 5: (K, L) = (8, 7), ETA 2, GAMMA1 2^19, GAMMA2 (q - 1)/32, BETA 120, TAU 60, OMEGA 75.

End of algorithm explanation.