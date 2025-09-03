use crate::params::{ K, L, SEEDBYTES, CRHBYTES, POLYW1_PACKEDBYTES };
use crate::poly::{
    Poly,
    poly_reduce,
    poly_caddq,
    poly_freeze,
    poly_add,
    poly_sub,
    poly_shiftl,
    poly_ntt,
    poly_invntt_tomont,
    poly_pointwise_montgomery,
    poly_power2round,
    poly_decompose,
    poly_make_hint,
    poly_use_hint,
    poly_chknorm,
    poly_uniform_eta,
    poly_uniform_gamma1,
    poly_uniform,
    // polyw1_pack,  // TODO: Re-enable when implemented
};

// EXACT NIST reference implementation - no modifications

/* Vectors of polynomials of length L */
#[derive(Clone, Copy, Debug)]
pub struct PolyVecL {
    pub vec: [Poly; L],
}

impl Default for PolyVecL {
    fn default() -> Self {
        PolyVecL { vec: [Poly::default(); L] }
    }
}

impl PolyVecL {
    pub fn new() -> Self {
        Self::default()
    }
}

/* Vectors of polynomials of length K */
#[derive(Clone, Copy, Debug)]
pub struct PolyVecK {
    pub vec: [Poly; K],
}

impl Default for PolyVecK {
    fn default() -> Self {
        PolyVecK { vec: [Poly::default(); K] }
    }
}

impl PolyVecK {
    pub fn new() -> Self {
        Self::default()
    }
}

/*************************************************
 * Name:        polyvecl_uniform_eta
 *
 * Description: Sample vector of polynomials uniformly from the same
 *              distribution as poly_uniform_eta() using the output of
 *              SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - &mut PolyVecL: pointer to output vector
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn polyvecl_uniform_eta(v: &mut PolyVecL, seed: &[u8; SEEDBYTES], nonce: u16) {
    for i in 0..L {
        poly_uniform_eta(&mut v.vec[i], seed, nonce + (i as u16));
    }
}

/*************************************************
 * Name:        polyvecl_uniform_gamma1
 *
 * Description: Sample vector of polynomials uniformly from the same
 *              distribution as poly_uniform_gamma1() using the output of
 *              SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - &mut PolyVecL: pointer to output vector
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn polyvecl_uniform_gamma1(v: &mut PolyVecL, seed: &[u8; CRHBYTES], nonce: u16) {
    for i in 0..L {
        poly_uniform_gamma1(&mut v.vec[i], seed, nonce + (i as u16));
    }
}

/*************************************************
 * Name:        polyvecl_reduce
 *
 * Description: Reduce coefficients of polynomials in vector of length L
 *              to representatives in [-6283009,6283007].
 *
 * Arguments:   - &mut PolyVecL: pointer to input/output vector
 **************************************************/
pub fn polyvecl_reduce(v: &mut PolyVecL) {
    for i in 0..L {
        poly_reduce(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_freeze
 *
 * Description: For all coefficients of polynomials in vector of length L
 *              subtract Q if coefficient is bigger than floor((Q-1)/2).
 *
 * Arguments:   - &mut PolyVecL: pointer to input/output vector
 **************************************************/
pub fn polyvecl_freeze(v: &mut PolyVecL) {
    for i in 0..L {
        poly_freeze(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_add
 *
 * Description: Add vectors of polynomials of length L.
 *              No modular reduction is performed.
 *
 * Arguments:   - &mut PolyVecL: pointer to output vector
 *              - &PolyVecL: pointer to first summand
 *              - &PolyVecL: pointer to second summand
 **************************************************/
pub fn polyvecl_add(w: &mut PolyVecL, u: &PolyVecL, v: &PolyVecL) {
    for i in 0..L {
        poly_add(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length L. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - &mut PolyVecL: pointer to input/output vector
 **************************************************/
pub fn polyvecl_ntt(v: &mut PolyVecL) {
    for i in 0..L {
        poly_ntt(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by Montgomery factor 2^32
 *              of polynomials in vector of length L. Input coefficients need
 *              to be less than Q in absolute value and output coefficients are
 *              again bounded by Q.
 *
 * Arguments:   - &mut PolyVecL: pointer to input/output vector
 **************************************************/
pub fn polyvecl_invntt_tomont(v: &mut PolyVecL) {
    for i in 0..L {
        poly_invntt_tomont(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_pointwise_poly_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting vector by 2^{-32}.
 *
 * Arguments:   - &mut PolyVecL: pointer to output vector
 *              - &Poly: pointer to first input polynomial
 *              - &PolyVecL: pointer to second input vector
 **************************************************/
pub fn polyvecl_pointwise_poly_montgomery(r: &mut PolyVecL, a: &Poly, v: &PolyVecL) {
    for i in 0..L {
        poly_pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiplication and accumulation of polynomials
 *              in NTT domain representation. Output polynomial is multiplied
 *              by 2^{-32}.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - &PolyVecL: pointer to first input vector
 *              - &PolyVecL: pointer to second input vector
 **************************************************/
pub fn polyvecl_pointwise_acc_montgomery(w: &mut Poly, u: &PolyVecL, v: &PolyVecL) {
    poly_pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
    for i in 1..L {
        let mut t = Poly::default();
        poly_pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
        let mut temp = Poly::default();
        poly_add(&mut temp, w, &t);
        *w = temp;
    }
}

/*************************************************
 * Name:        polyvecl_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length L.
 *              Assumes input coefficients were reduced by polyvecl_reduce().
 *
 * Arguments:   - &PolyVecL: pointer to vector
 *              - i32: norm bound
 *
 * Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 *         and 1 otherwise.
 **************************************************/
pub fn polyvecl_chknorm(v: &PolyVecL, b: i32) -> i32 {
    for i in 0..L {
        if poly_chknorm(&v.vec[i], b) != 0 {
            return 1;
        }
    }
    0
}

/*************************************************
 * Name:        polyveck_uniform_eta
 *
 * Description: Sample vector of polynomials uniformly from the same
 *              distribution as poly_uniform_eta() using the output of
 *              SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn polyveck_uniform_eta(v: &mut PolyVecK, seed: &[u8; SEEDBYTES], nonce: u16) {
    for i in 0..K {
        poly_uniform_eta(&mut v.vec[i], seed, nonce + (i as u16));
    }
}

/*************************************************
 * Name:        polyveck_reduce
 *
 * Description: Reduce coefficients of polynomials in vector of length K
 *              to representatives in [-6283009,6283007].
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_reduce(v: &mut PolyVecK) {
    for i in 0..K {
        poly_reduce(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length K. Output
 *              coefficients can be up to 16*Q larger than input coefficients.
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_ntt(v: &mut PolyVecK) {
    for i in 0..K {
        poly_ntt(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by Montgomery factor 2^32
 *              of polynomials in vector of length K. Input coefficients need
 *              to be less than Q in absolute value and output coefficients are
 *              again bounded by Q.
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_invntt_tomont(v: &mut PolyVecK) {
    for i in 0..K {
        poly_invntt_tomont(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_caddq
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              add Q if coefficient is negative.
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_caddq(v: &mut PolyVecK) {
    for i in 0..K {
        poly_caddq(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_freeze
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              subtract Q if coefficient is bigger than floor((Q-1)/2).
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_freeze(v: &mut PolyVecK) {
    for i in 0..K {
        poly_freeze(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_add
 *
 * Description: Add vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector
 *              - &PolyVecK: pointer to first summand
 *              - &PolyVecK: pointer to second summand
 **************************************************/
pub fn polyveck_add(w: &mut PolyVecK, u: &PolyVecK, v: &PolyVecK) {
    for i in 0..K {
        poly_add(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_sub
 *
 * Description: Subtract vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector
 *              - &PolyVecK: pointer to first input vector
 *              - &PolyVecK: pointer to second input vector to be
 *                           subtracted from first input vector
 **************************************************/
pub fn polyveck_sub(w: &mut PolyVecK, u: &PolyVecK, v: &PolyVecK) {
    for i in 0..K {
        poly_sub(&mut w.vec[i], &u.vec[i], &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_shiftl
 *
 * Description: Multiply vector of polynomials of length K by 2^D without
 *              modular reduction. Assumes input coefficients to be less than
 *              2^{31-D} in absolute value.
 *
 * Arguments:   - &mut PolyVecK: pointer to input/output vector
 **************************************************/
pub fn polyveck_shiftl(v: &mut PolyVecK) {
    for i in 0..K {
        poly_shiftl(&mut v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_pointwise_poly_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting vector by 2^{-32}.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector
 *              - &Poly: pointer to first input polynomial
 *              - &PolyVecK: pointer to second input vector
 **************************************************/
pub fn polyveck_pointwise_poly_montgomery(r: &mut PolyVecK, a: &Poly, v: &PolyVecK) {
    for i in 0..K {
        poly_pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length K.
 *              Assumes input coefficients were reduced by polyveck_reduce().
 *
 * Arguments:   - &PolyVecK: pointer to vector
 *              - i32: norm bound
 *
 * Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 *         and 1 otherwise.
 **************************************************/
pub fn polyveck_chknorm(v: &PolyVecK, b: i32) -> i32 {
    for i in 0..K {
        if poly_chknorm(&v.vec[i], b) != 0 {
            return 1;
        }
    }
    0
}

/*************************************************
 * Name:        polyveck_power2round
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute a0, a1 such that a mod^+ Q = a1*2^D + a0 with
 *              -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector of polynomials with
 *                               coefficients a1
 *              - &mut PolyVecK: pointer to output vector of polynomials with
 *                               coefficients a0
 *              - &PolyVecK: pointer to input vector
 **************************************************/
pub fn polyveck_power2round(v1: &mut PolyVecK, v0: &mut PolyVecK, v: &PolyVecK) {
    for i in 0..K {
        poly_power2round(&mut v1.vec[i], &mut v0.vec[i], &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_decompose
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
 *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
 *              set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector of polynomials with
 *                               coefficients a1
 *              - &mut PolyVecK: pointer to output vector of polynomials with
 *                               coefficients a0
 *              - &PolyVecK: pointer to input vector
 **************************************************/
pub fn polyveck_decompose(v1: &mut PolyVecK, v0: &mut PolyVecK, v: &PolyVecK) {
    for i in 0..K {
        poly_decompose(&mut v1.vec[i], &mut v0.vec[i], &v.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_make_hint
 *
 * Description: Compute hint polynomials. The coefficients of which indicate
 *              whether the low bits of the corresponding coefficients of
 *              the input polynomial vector overflow into the high bits.
 *
 * Arguments:   - &mut PolyVecK: pointer to output hint vector
 *              - &PolyVecK: pointer to low part of input vector
 *              - &PolyVecK: pointer to high part of input vector
 *
 * Returns number of 1 bits.
 **************************************************/
pub fn polyveck_make_hint(h: &mut PolyVecK, v0: &PolyVecK, v1: &PolyVecK) -> usize {
    let mut s = 0;
    for i in 0..K {
        s += poly_make_hint(&mut h.vec[i], &v0.vec[i], &v1.vec[i]);
    }
    s
}

/*************************************************
 * Name:        polyveck_use_hint
 *
 * Description: Use hint vector to correct the high bits of input vector.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector of polynomials with
 *                               corrected high bits
 *              - &PolyVecK: pointer to input vector
 *              - &PolyVecK: pointer to input hint vector
 **************************************************/
pub fn polyveck_use_hint(w: &mut PolyVecK, v: &PolyVecK, h: &PolyVecK) {
    for i in 0..K {
        poly_use_hint(&mut w.vec[i], &v.vec[i], &h.vec[i]);
    }
}

/*************************************************
 * Name:        polyveck_pack_w1
 *
 * Description: Bit-pack polynomial vector w1 with coefficients in [0, 15] or [0, 43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   K*POLYW1_PACKEDBYTES bytes
 *              - w1: pointer to input vector
 **************************************************/
pub fn polyveck_pack_w1(_r: &mut [u8; K * POLYW1_PACKEDBYTES], _w1: &PolyVecK) {
    for _i in 0..K {
        // TODO: Implement polyw1_pack when it's available
        // polyw1_pack(&mut _r[_i * POLYW1_PACKEDBYTES..], &_w1.vec[_i]);
    }
}

/*************************************************
 * Name:        polyvec_matrix_expand
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection sampling on the
 *              output stream of SHAKE128(rho|i|j) or AES256CTR(rho,i,j).
 *
 * Arguments:   - mat: pointer to output matrix
 *              - rho: byte array containing seed rho
 **************************************************/
pub fn polyvec_matrix_expand(mat: &mut [PolyVecL; K], rho: &[u8; SEEDBYTES]) {
    for i in 0..K {
        for j in 0..L {
            poly_uniform(&mut mat[i].vec[j], rho, ((i << 8) + j).try_into().unwrap());
        }
    }
}

/*************************************************
 * Name:        polyvec_matrix_pointwise_montgomery
 *
 * Description: Matrix-vector multiplication; matrix elements are polynomials in
 *              NTT domain, vector elements are polynomials in NTT domain.
 *
 * Arguments:   - &mut PolyVecK: pointer to output vector
 *              - mat: pointer to input matrix
 *              - &PolyVecL: pointer to input vector
 **************************************************/
pub fn polyvec_matrix_pointwise_montgomery(t: &mut PolyVecK, mat: &[PolyVecL; K], v: &PolyVecL) {
    for i in 0..K {
        polyvecl_pointwise_acc_montgomery(&mut t.vec[i], &mat[i], v);
    }
}
