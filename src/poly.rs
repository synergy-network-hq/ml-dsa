use crate::params::{ N, Q, D, GAMMA2, TAU, CRHBYTES, ETA, GAMMA1 };
use crate::reduce::{ reduce32, caddq, freeze, montgomery_reduce };
use crate::ntt::{ ntt, invntt_tomont };
use crate::symmetric::{
    SHAKE256_RATE,
    STREAM128_BLOCKBYTES,
    STREAM256_BLOCKBYTES,
    Stream256State,
    stream256_init,
    stream256_squeezeblocks,
};

// EXACT NIST reference implementation - no modifications

#[derive(Clone, Copy, Debug)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly { coeffs: [0; N] }
    }
}

impl Poly {
    pub fn new() -> Self {
        Self::default()
    }
}

/*************************************************
 * Name:        poly_reduce
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283009,6283007].
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_reduce(a: &mut Poly) {
    for i in 0..N {
        a.coeffs[i] = reduce32(a.coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_caddq
 *
 * Description: For all coefficients of in/out polynomial add Q if
 *              coefficient is negative.
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_caddq(a: &mut Poly) {
    for i in 0..N {
        a.coeffs[i] = caddq(a.coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_freeze
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              standard representatives.
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_freeze(a: &mut Poly) {
    for i in 0..N {
        a.coeffs[i] = freeze(a.coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - &Poly: pointer to first summand
 *              - &Poly: pointer to second summand
 **************************************************/
pub fn poly_add(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
    }
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - &Poly: pointer to first input polynomial
 *              - &Poly: pointer to second input polynomial
 **************************************************/
pub fn poly_sub(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }
}

/*************************************************
 * Name:        poly_shiftl
 *
 * Description: Multiply polynomial by 2^D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-D} in absolute value.
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_shiftl(a: &mut Poly) {
    for i in 0..N {
        a.coeffs[i] <<= D;
    }
}

/*************************************************
 * Name:        poly_ntt
 *
 * Description: Inplace forward NTT. Coefficients can grow by
 *              8*Q in absolute value.
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_ntt(a: &mut Poly) {
    ntt(&mut a.coeffs);
}

/*************************************************
 * Name:        poly_invntt_tomont
 *
 * Description: Inplace inverse NTT and multiplication by 2^{32}.
 *              Input coefficients need to be less than Q in absolute
 *              value and output coefficients are again bounded by Q.
 *
 * Arguments:   - &mut Poly: pointer to input/output polynomial
 **************************************************/
pub fn poly_invntt_tomont(a: &mut Poly) {
    invntt_tomont(&mut a.coeffs);
}

/*************************************************
 * Name:        poly_pointwise_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - &Poly: pointer to first input polynomial
 *              - &Poly: pointer to second input polynomial
 **************************************************/
pub fn poly_pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c.coeffs[i] = montgomery_reduce((a.coeffs[i] as i64) * (b.coeffs[i] as i64));
    }
}

/*************************************************
 * Name:        poly_power2round
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute c0, c1 such that c mod Q = c1*2^D + c0
 *              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial with coefficients c1
 *              - &mut Poly: pointer to output polynomial with coefficients c0
 *              - &Poly: pointer to input polynomial
 **************************************************/
pub fn poly_power2round(a1: &mut Poly, a0: &mut Poly, a: &Poly) {
    for i in 0..N {
        a1.coeffs[i] = power2round(&mut a0.coeffs[i], a.coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_decompose
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
 *              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
 *              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial with coefficients c1
 *              - &mut Poly: pointer to output polynomial with coefficients c0
 *              - &Poly: pointer to input polynomial
 **************************************************/
pub fn poly_decompose(a1: &mut Poly, a0: &mut Poly, a: &Poly) {
    for i in 0..N {
        a1.coeffs[i] = decompose(&mut a0.coeffs[i], a.coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_make_hint
 *
 * Description: Compute hint polynomial. The coefficients of which indicate
 *              whether the low bits of the corresponding coefficient of
 *              the input polynomial overflow into the high bits.
 *
 * Arguments:   - &mut Poly: pointer to output hint polynomial
 *              - &Poly: pointer to low part of input polynomial
 *              - &Poly: pointer to high part of input polynomial
 *
 * Returns number of 1 bits.
 **************************************************/
pub fn poly_make_hint(h: &mut Poly, a0: &Poly, a1: &Poly) -> usize {
    let mut s = 0;
    for i in 0..N {
        h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i]) as i32;
        s += h.coeffs[i] as usize;
    }
    s
}

/*************************************************
 * Name:        poly_use_hint
 *
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 *
 * Arguments:   - &mut Poly: pointer to output polynomial with corrected high bits
 *              - &Poly: pointer to input polynomial
 *              - &Poly: pointer to input hint polynomial
 **************************************************/
pub fn poly_use_hint(b: &mut Poly, a: &Poly, h: &Poly) {
    for i in 0..N {
        b.coeffs[i] = use_hint(a.coeffs[i], h.coeffs[i] as u32);
    }
}

/*************************************************
 * Name:        poly_chknorm
 *
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input coefficients were reduced by reduce32().
 *
 * Arguments:   - &Poly: pointer to polynomial
 *              - i32: norm bound
 *
 * Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 **************************************************/
pub fn poly_chknorm(a: &Poly, b: i32) -> i32 {
    if b > ((Q as i32) - 1) / 8 {
        return 1;
    }

    for i in 0..N {
        let mut t = a.coeffs[i] >> 31;
        t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

        if t >= b {
            return 1;
        }
    }
    0
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, Q-1] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - &mut [i32]: pointer to output array (allocated)
 *              - len: number of coefficients to be sampled
 *              - buf: array of random bytes
 *              - buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
fn rej_uniform(a: &mut [i32], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < len && pos + 3 <= buflen {
        let mut t = buf[pos] as u32;
        pos += 1;
        t |= (buf[pos] as u32) << 8;
        pos += 1;
        t |= (buf[pos] as u32) << 16;
        pos += 1;
        t &= 0x7fffff;

        if t < (Q as u32) {
            a[ctr] = t as i32;
            ctr += 1;
        }
    }
    ctr
}

/*************************************************
 * Name:        poly_uniform
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,Q-1] by performing rejection sampling on the
 *              output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
const POLY_UNIFORM_NBLOCKS: usize = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;

pub fn poly_uniform(a: &mut Poly, seed: &[u8; 32], nonce: u16) {
    use crate::symmetric::{ stream128_init, stream128_squeezeblocks };

    let mut ctr;
    let mut off;
    let mut buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
    let mut buf = vec![0u8; POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2];
    let mut state = crate::symmetric::Stream128State::default();

    stream128_init(&mut state, seed, nonce);
    stream128_squeezeblocks(&mut buf, POLY_UNIFORM_NBLOCKS, &mut state);

    ctr = rej_uniform(&mut a.coeffs, N, &buf, buflen);

    while ctr < N {
        off = buflen % 3;
        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }

        stream128_squeezeblocks(&mut buf[off..], 1, &mut state);
        buflen = STREAM128_BLOCKBYTES + off;
        ctr += rej_uniform(&mut a.coeffs[ctr..], N - ctr, &buf, buflen);
    }
}

/*************************************************
 * Name:        poly_uniform_eta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-ETA,ETA] by performing rejection sampling on the
 *              output stream from SHAKE256(seed|nonce).
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn poly_uniform_eta(a: &mut Poly, seed: &[u8; 32], nonce: u16) {
    crate::cbd::poly_uniform_eta(&mut a.coeffs, seed, nonce);
}

/*************************************************
 * Name:        poly_challenge
 *
 * Description: Implementation of H. Samples polynomial with TAU nonzero
 *              coefficients in {-1,1} using the output stream of
 *              SHAKE256(seed).
 *
 * Arguments:   - &mut Poly: pointer to output polynomial
 *              - seed: byte array containing seed of length SEEDBYTES
 **************************************************/
pub fn poly_challenge(c: &mut Poly, seed: &[u8; 32]) {
    use crate::symmetric::{
        shake256_init,
        shake256_absorb,
        shake256_finalize,
        shake256_squeezeblocks,
    };

    let mut _i: usize;
    let mut b: usize;
    let mut pos: usize;
    let mut signs: u64;
    let mut buf = [0u8; SHAKE256_RATE];
    let mut state = crate::symmetric::KeccakState::default();

    shake256_init(&mut state);
    shake256_absorb(&mut state, seed);
    shake256_finalize(&mut state);
    shake256_squeezeblocks(&mut buf, 1, &mut state);

    signs = 0;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }
    pos = 8;

    for i in 0..N {
        c.coeffs[i] = 0;
    }
    for i in N - TAU..N {
        loop {
            if pos >= SHAKE256_RATE {
                shake256_squeezeblocks(&mut buf, 1, &mut state);
                pos = 0;
            }

            b = buf[pos] as usize;
            pos += 1;

            if b < i {
                c.coeffs[i] = if (signs & 1) != 0 { 1 } else { -1 };
                signs >>= 1;
                break;
            }
        }
    }
}

/*************************************************
 * Name:        poly_uniform_gamma1
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
 *              of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
 *
 * Arguments:   - a: pointer to output polynomial
 *              - seed: byte array with seed of length CRHBYTES
 *              - nonce: 16-bit nonce
 **************************************************/
pub fn poly_uniform_gamma1(a: &mut Poly, seed: &[u8; CRHBYTES], nonce: u16) {
    const POLY_UNIFORM_GAMMA1_NBLOCKS: usize =
        (640 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;

    let mut buf = [0u8; POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];
    let mut state = Stream256State::default();

    stream256_init(&mut state, seed, nonce);
    stream256_squeezeblocks(&mut buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &mut state);
    polyz_unpack(a, &buf);
}

// Helper functions from rounding.c - EXACT implementations
/*************************************************
 * Name:        power2round
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 *              Assumes a to be standard representative.
 *
 * Arguments:   - a: input element
 *              - a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
fn power2round(a0: &mut i32, a: i32) -> i32 {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    a1
}

/*************************************************
 * Name:        decompose
 *
 * Description: For finite field element a, compute high and low bits a0, a1 such
 *              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
 *              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
 *              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
 *              representative.
 *
 * Arguments:   - a: input element
 *              - a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
fn decompose(a0: &mut i32, a: i32) -> i32 {
    let mut a1 = (a + 127) >> 7;
    if GAMMA2 == 261888 {
        // (Q-1)/32
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if GAMMA2 == 95232 {
        // (Q-1)/88
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    *a0 = a - a1 * 2 * (GAMMA2 as i32);
    *a0 -= ((((Q as i32) - 1) / 2 - *a0) >> 31) & (Q as i32);
    a1
}

/*************************************************
 * Name:        make_hint
 *
 * Description: Compute hint bit indicating whether the low bits of the
 *              input element overflow into the high bits. Inputs assumed
 *              to be standard representatives.
 *
 * Arguments:   - a0: low bits of input element
 *              - a1: high bits of input element
 *
 * Returns 1 if overflow.
 **************************************************/
fn make_hint(a0: i32, a1: i32) -> u32 {
    if
        a0 <= (GAMMA2 as i32) ||
        a0 > (Q as i32) - (GAMMA2 as i32) ||
        (a0 == (Q as i32) - (GAMMA2 as i32) && a1 == 0)
    {
        0
    } else {
        1
    }
}

/*************************************************
 * Name:        use_hint
 *
 * Description: Correct high bits according to hint.
 *
 * Arguments:   - a: input element
 *              - hint: hint bit
 *
 * Returns corrected high bits.
 **************************************************/
fn use_hint(a: i32, hint: u32) -> i32 {
    let mut a0 = 0;
    let a1 = decompose(&mut a0, a);
    if hint == 0 {
        return a1;
    }

    if GAMMA2 == 261888 {
        // (Q-1)/32
        if a0 > 0 {
            return (a1 + 1) & 15;
        } else {
            return (a1 - 1) & 15;
        }
    } else if GAMMA2 == 95232 {
        // (Q-1)/88
        if a0 > 0 {
            return if a1 == 43 { 0 } else { a1 + 1 };
        } else {
            return if a1 == 0 { 43 } else { a1 - 1 };
        }
    }
    a1
}

/*************************************************
 * Name:        polyeta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   POLYETA_PACKEDBYTES bytes
 *              - a: pointer to input polynomial
 **************************************************/
// TODO: Implement polyeta_pack function - temporarily commented out to fix warnings
// pub fn polyeta_pack(r: &mut [u8], a: &Poly) {
//     let t = [0u8; 8];
//
//     #[cfg(feature = "eta2")]
//     for i in 0..N / 8 {
//         t[0] = (ETA as u8) - (a.coeffs[8 * i + 0] as u8);
//         t[1] = (ETA as u8) - (a.coeffs[8 * i + 1] as u8);
//         t[2] = (ETA as u8) - (a.coeffs[8 * i + 2] as u8);
//         t[3] = (ETA as u8) - (a.coeffs[8 * i + 3] as u8);
//         t[4] = (ETA as u8) - (a.coeffs[8 * i + 4] as u8);
//         t[5] = (ETA as u8) - (a.coeffs[8 * i + 5] as u8);
//         t[6] = (ETA as u8) - (a.coeffs[8 * i + 6] as u8);
//         t[7] = (ETA as u8) - (a.coeffs[8 * i + 7] as u8);
//
//         r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
//         r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
//         r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
//     }
//
//     #[cfg(feature = "eta4")]
//     for i in 0..N / 2 {
//         t[0] = (ETA as u8) - (a.coeffs[2 * i + 0] as u8);
//         t[1] = (ETA as u8) - (a.coeffs[2 * i + 1] as u8);
//         r[i] = t[0] | (t[1] << 4);
//     }
// }

/*************************************************
 * Name:        polyeta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - r: pointer to output polynomial
 *              - a: byte array with bit-packed polynomial
 **************************************************/
pub fn polyeta_unpack(_r: &mut Poly, _a: &[u8]) {
    for i in 0..N / 8 {
        _r.coeffs[8 * i + 0] = ((_a[3 * i + 0] >> 0) & 7) as i32;
        _r.coeffs[8 * i + 1] = ((_a[3 * i + 0] >> 3) & 7) as i32;
        _r.coeffs[8 * i + 2] = (((_a[3 * i + 0] >> 6) as u32 | ((_a[3 * i + 1] as u32) << 2)) & 7) as i32;
        _r.coeffs[8 * i + 3] = ((_a[3 * i + 1] >> 1) & 7) as i32;
        _r.coeffs[8 * i + 4] = ((_a[3 * i + 1] >> 4) & 7) as i32;
        _r.coeffs[8 * i + 5] = (((_a[3 * i + 1] >> 7) as u32 | ((_a[3 * i + 2] as u32) << 1)) & 7) as i32;
        _r.coeffs[8 * i + 6] = ((_a[3 * i + 1] >> 2) & 7) as i32;
        _r.coeffs[8 * i + 7] = ((_a[3 * i + 1] >> 5) & 7) as i32;

        _r.coeffs[8 * i + 0] = (ETA as i32) - _r.coeffs[8 * i + 0];
        _r.coeffs[8 * i + 1] = (ETA as i32) - _r.coeffs[8 * i + 1];
        _r.coeffs[8 * i + 2] = (ETA as i32) - _r.coeffs[8 * i + 2];
        _r.coeffs[8 * i + 3] = (ETA as i32) - _r.coeffs[8 * i + 3];
        _r.coeffs[8 * i + 4] = (ETA as i32) - _r.coeffs[8 * i + 4];
        _r.coeffs[8 * i + 5] = (ETA as i32) - _r.coeffs[8 * i + 5];
        _r.coeffs[8 * i + 6] = (ETA as i32) - _r.coeffs[8 * i + 6];
        _r.coeffs[8 * i + 7] = (ETA as i32) - _r.coeffs[8 * i + 7];
    }
}

/*************************************************
 * Name:        polyt1_pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   POLYT1_PACKEDBYTES bytes
 *              - a: pointer to input polynomial
 **************************************************/
pub fn polyt1_pack(r: &mut [u8], a: &Poly) {
    for i in 0..N / 4 {
        r[5 * i + 0] = (a.coeffs[4 * i + 0] >> 0) as u8;
        r[5 * i + 1] = ((a.coeffs[4 * i + 0] >> 8) | (a.coeffs[4 * i + 1] << 2)) as u8;
        r[5 * i + 2] = ((a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4)) as u8;
        r[5 * i + 3] = ((a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6)) as u8;
        r[5 * i + 4] = (a.coeffs[4 * i + 3] >> 2) as u8;
    }
}

/*************************************************
 * Name:        polyt1_unpack
 *
 * Description: Unpack polynomial t1 with 10-bit coefficients.
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - r: pointer to output polynomial
 *              - a: byte array with bit-packed polynomial
 **************************************************/
pub fn polyt1_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        r.coeffs[4 * i + 0] =
            ((((a[5 * i + 0] as u32) >> 0) | ((a[5 * i + 1] as u32) << 8)) as i32) & 0x3ff;
        r.coeffs[4 * i + 1] =
            ((((a[5 * i + 1] as u32) >> 2) | ((a[5 * i + 2] as u32) << 6)) as i32) & 0x3ff;
        r.coeffs[4 * i + 2] =
            ((((a[5 * i + 2] as u32) >> 4) | ((a[5 * i + 3] as u32) << 4)) as i32) & 0x3ff;
        r.coeffs[4 * i + 3] =
            ((((a[5 * i + 3] as u32) >> 6) | ((a[5 * i + 4] as u32) << 2)) as i32) & 0x3ff;
    }
}

/*************************************************
 * Name:        polyt0_pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   POLYT0_PACKEDBYTES bytes
 *              - a: pointer to input polynomial
 **************************************************/
pub fn polyt0_pack(r: &mut [u8], a: &Poly) {
    let mut t = [0u32; 8];

    for i in 0..N / 8 {
        // Do the arithmetic in signed integer domain first, like the C reference implementation
        t[0] = ((1 << (D - 1)) - a.coeffs[8 * i + 0]) as u32;
        t[1] = ((1 << (D - 1)) - a.coeffs[8 * i + 1]) as u32;
        t[2] = ((1 << (D - 1)) - a.coeffs[8 * i + 2]) as u32;
        t[3] = ((1 << (D - 1)) - a.coeffs[8 * i + 3]) as u32;
        t[4] = ((1 << (D - 1)) - a.coeffs[8 * i + 4]) as u32;
        t[5] = ((1 << (D - 1)) - a.coeffs[8 * i + 5]) as u32;
        t[6] = ((1 << (D - 1)) - a.coeffs[8 * i + 6]) as u32;
        t[7] = ((1 << (D - 1)) - a.coeffs[8 * i + 7]) as u32;

        r[13 * i + 0] = t[0] as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8;
        r[13 * i + 1] |= (t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8;
        r[13 * i + 3] |= (t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6) as u8;
        r[13 * i + 4] |= (t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8;
        r[13 * i + 6] |= (t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8;
        r[13 * i + 8] |= (t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7) as u8;
        r[13 * i + 9] |= (t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8;
        r[13 * i + 11] |= (t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/*************************************************
 * Name:        polyt0_unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - r: pointer to output polynomial
 *              - a: byte array with bit-packed polynomial
 **************************************************/
pub fn polyt0_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 8 {
        // First unpack as unsigned integers, exactly like the C reference implementation
        // Store directly into r.coeffs as u32 values, just like the C version
        r.coeffs[8 * i + 0] = a[13 * i + 0] as i32;
        r.coeffs[8 * i + 0] |= (a[13 * i + 1] as i32) << 8;
        r.coeffs[8 * i + 0] &= 0x1fff;

        r.coeffs[8 * i + 1] = (a[13 * i + 1] >> 5) as i32;
        r.coeffs[8 * i + 1] |= (a[13 * i + 2] as i32) << 3;
        r.coeffs[8 * i + 1] |= (a[13 * i + 3] as i32) << 11;
        r.coeffs[8 * i + 1] &= 0x1fff;

        r.coeffs[8 * i + 2] = (a[13 * i + 3] >> 2) as i32;
        r.coeffs[8 * i + 2] |= (a[13 * i + 4] as i32) << 6;
        r.coeffs[8 * i + 2] &= 0x1fff;

        r.coeffs[8 * i + 3] = (a[13 * i + 4] >> 7) as i32;
        r.coeffs[8 * i + 3] |= (a[13 * i + 5] as i32) << 1;
        r.coeffs[8 * i + 3] |= (a[13 * i + 6] as i32) << 9;
        r.coeffs[8 * i + 3] &= 0x1fff;

        r.coeffs[8 * i + 4] = (a[13 * i + 6] >> 4) as i32;
        r.coeffs[8 * i + 4] |= (a[13 * i + 7] as i32) << 4;
        r.coeffs[8 * i + 4] |= (a[13 * i + 8] as i32) << 12;
        r.coeffs[8 * i + 4] &= 0x1fff;

        r.coeffs[8 * i + 5] = (a[13 * i + 8] >> 1) as i32;
        r.coeffs[8 * i + 5] |= (a[13 * i + 9] as i32) << 7;
        r.coeffs[8 * i + 5] &= 0x1fff;

        r.coeffs[8 * i + 6] = (a[13 * i + 9] >> 6) as i32;
        r.coeffs[8 * i + 6] |= (a[13 * i + 10] as i32) << 2;
        r.coeffs[8 * i + 6] |= (a[13 * i + 11] as i32) << 10;
        r.coeffs[8 * i + 6] &= 0x1fff;

        r.coeffs[8 * i + 7] = (a[13 * i + 11] >> 3) as i32;
        r.coeffs[8 * i + 7] |= (a[13 * i + 12] as i32) << 5;
        r.coeffs[8 * i + 7] &= 0x1fff;

        // Then do the subtraction exactly like the C reference implementation
        r.coeffs[8 * i + 0] = (1 << (D - 1)) - r.coeffs[8 * i + 0];
        r.coeffs[8 * i + 1] = (1 << (D - 1)) - r.coeffs[8 * i + 1];
        r.coeffs[8 * i + 2] = (1 << (D - 1)) - r.coeffs[8 * i + 2];
        r.coeffs[8 * i + 3] = (1 << (D - 1)) - r.coeffs[8 * i + 3];
        r.coeffs[8 * i + 4] = (1 << (D - 1)) - r.coeffs[8 * i + 4];
        r.coeffs[8 * i + 5] = (1 << (D - 1)) - r.coeffs[8 * i + 5];
        r.coeffs[8 * i + 6] = (1 << (D - 1)) - r.coeffs[8 * i + 6];
        r.coeffs[8 * i + 7] = (1 << (D - 1)) - r.coeffs[8 * i + 7];
    }
}

/*************************************************
 * Name:        polyz_pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   POLYZ_PACKEDBYTES bytes
 *              - a: pointer to input polynomial
 **************************************************/
// TODO: Implement polyz_pack function - temporarily commented out to fix warnings
// pub fn polyz_pack(r: &mut [u8], a: &Poly) {
//     let t = [0u32; 4];
//
//     #[cfg(feature = "gamma1_17")]
//     for i in 0..N / 4 {
//         // Do the arithmetic in signed integer domain first, like the C reference implementation
//         t[0] = (GAMMA1 - a.coeffs[4 * i + 0]) as u32;
//         t[1] = (GAMMA1 - a.coeffs[4 * i + 1]) as u32;
//         t[2] = (GAMMA1 - a.coeffs[4 * i + 2]) as u32;
//         t[3] = (GAMMA1 - a.coeffs[4 * i + 3]) as u32;
//
//         r[9 * i + 0] = t[0] as u8;
//         r[9 * i + 1] = (t[0] >> 8) as u8;
//         r[9 * i + 2] = (t[0] >> 16) as u8;
//         r[9 * i + 2] |= (t[1] << 2) as u8;
//         r[9 * i + 3] = (t[1] >> 6) as u8;
//         r[9 * i + 4] = (t[1] >> 14) as u8;
//         r[9 * i + 4] |= (t[2] << 4) as u8;
//         r[9 * i + 5] = (t[2] >> 4) as u8;
//         r[9 * i + 6] = (t[2] >> 12) as u8;
//         r[9 * i + 6] |= (t[3] << 6) as u8;
//         r[9 * i + 7] = (t[3] >> 2) as u8;
//         r[9 * i + 8] = (t[3] >> 10) as u8;
//     }
//
//     #[cfg(feature = "gamma1_19")]
//     for i in 0..N / 2 {
//         // Do the arithmetic in signed integer domain first, like the C reference implementation
//         t[0] = (GAMMA1 - a.coeffs[2 * i + 0]) as u32;
//         t[1] = (GAMMA1 - a.coeffs[2 * i + 1]) as u32;
//
//         r[5 * i + 0] = t[0] as u8;
//         r[5 * i + 1] = (t[0] >> 8) as u8;
//         r[5 * i + 2] = (t[0] >> 16) as u8;
//         r[5 * i + 2] |= (t[1] << 4) as u8;
//         r[5 * i + 3] = (t[1] >> 4) as u8;
//         r[5 * i + 4] = (t[1] >> 12) as u8;
//     }
// }

/*************************************************
 * Name:        polyz_unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - r: pointer to output polynomial
 *              - a: byte array with bit-packed polynomial
 **************************************************/
pub fn polyz_unpack(_r: &mut Poly, _a: &[u8]) {
    for i in 0..N / 4 {
        _r.coeffs[4 * i + 0] = _a[9 * i + 0] as i32;
        _r.coeffs[4 * i + 0] |= (_a[9 * i + 1] as i32) << 8;
        _r.coeffs[4 * i + 0] |= (_a[9 * i + 2] as i32) << 16;
        _r.coeffs[4 * i + 0] &= 0x3ffff;
        _r.coeffs[4 * i + 1] = (_a[9 * i + 2] >> 6) as i32;
        _r.coeffs[4 * i + 1] |= (_a[9 * i + 3] as i32) << 2;
        _r.coeffs[4 * i + 1] |= (_a[9 * i + 4] as i32) << 10;
        _r.coeffs[4 * i + 1] |= (_a[9 * i + 5] as i32) << 18;
        _r.coeffs[4 * i + 1] &= 0x3ffff;
        _r.coeffs[4 * i + 2] = (_a[9 * i + 5] >> 4) as i32;
        _r.coeffs[4 * i + 2] |= (_a[9 * i + 6] as i32) << 4;
        _r.coeffs[4 * i + 2] |= (_a[9 * i + 7] as i32) << 12;
        _r.coeffs[4 * i + 2] |= (_a[9 * i + 8] as i32) << 20;
        _r.coeffs[4 * i + 2] &= 0x3ffff;
        _r.coeffs[4 * i + 3] = (_a[9 * i + 6] >> 6) as i32;
        _r.coeffs[4 * i + 3] |= (_a[9 * i + 7] as i32) << 2;
        _r.coeffs[4 * i + 3] |= (_a[9 * i + 8] as i32) << 10;
        _r.coeffs[4 * i + 3] &= 0x3ffff;

        _r.coeffs[4 * i + 0] = (GAMMA1 as i32) - _r.coeffs[4 * i + 0];
        _r.coeffs[4 * i + 1] = (GAMMA1 as i32) - _r.coeffs[4 * i + 1];
        _r.coeffs[4 * i + 2] = (GAMMA1 as i32) - _r.coeffs[4 * i + 2];
        _r.coeffs[4 * i + 3] = (GAMMA1 as i32) - _r.coeffs[4 * i + 3];
    }
}

/*************************************************
 * Name:        polyw1_pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - r: pointer to output byte array with at least
 *                   POLYW1_PACKEDBYTES bytes
 *              - a: pointer to input polynomial
 **************************************************/
// TODO: Implement polyw1_pack function - temporarily commented out to fix warnings
// pub fn polyw1_pack(r: &mut [u8], a: &Poly) {
//     #[cfg(feature = "gamma2_88")]
//     for i in 0..N / 2 {
//         r[i] = a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4);
//     }
//
//     #[cfg(feature = "gamma2_32")]
//     for i in 0..N / 4 {
//         r[3 * i + 0] = (a.coeffs[4 * i + 0] >> 0) | (a.coeffs[4 * i + 1] << 6);
//         r[3 * i + 1] = (a.coeffs[4 * i + 1] >> 2) | (a.coeffs[4 * i + 2] << 4);
//         r[3 * i + 2] = (a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 2);
//     }
// }
