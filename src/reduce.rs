use crate::params::Q;

// EXACT NIST reference implementation - no modifications

pub const MONT: i32 = -4186625; // 2^32 % Q
pub const QINV: i32 = 58728449; // q^(-1) mod 2^32

/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
 *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * Arguments:   - i64: finite field element a
 *
 * Returns r.
 **************************************************/
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = ((a & 0xffffffff) as i64) * (QINV as i64);
    let t = (a - (t & 0xffffffff) * (Q as i64)) >> 32;
    t as i32
}

/*************************************************
 * Name:        reduce32
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    let t = a - t * (Q as i32);
    t
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add Q if input coefficient is negative.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
pub fn caddq(a: i32) -> i32 {
    let mut result = a;
    result += (result >> 31) & (Q as i32);
    result
}

/*************************************************
 * Name:        freeze
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ Q.
 *
 * Arguments:   - i32: finite field element a
 *
 * Returns r.
 **************************************************/
pub fn freeze(a: i32) -> i32 {
    let mut result = reduce32(a);
    result = caddq(result);
    result
}
