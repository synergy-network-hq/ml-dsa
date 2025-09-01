use crate::params::{ N, ETA };

// EXACT NIST reference implementation - no modifications

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-ETA, ETA] by
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
pub fn rej_eta(a: &mut [i32], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < len && pos < buflen {
        let t0 = (buf[pos] & 0x0f) as u32;
        let t1 = (buf[pos] >> 4) as u32;
        pos += 1;

        if ETA == 4 {
            if t0 < 9 {
                a[ctr] = 4 - (t0 as i32);
                ctr += 1;
            }
            if t1 < 9 && ctr < len {
                a[ctr] = 4 - (t1 as i32);
                ctr += 1;
            }
        }
    }

    ctr
}

/*************************************************
 * Name:        poly_uniform_eta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-ETA,ETA] by performing rejection sampling on the
 *              output stream from SHAKE256(seed|nonce).
 *
 * Arguments:   - &mut [i32; N]: pointer to output polynomial
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn poly_uniform_eta(a: &mut [i32; N], seed: &[u8; 32], nonce: u16) {
    use crate::symmetric::{ stream128_init, stream128_squeezeblocks, STREAM128_BLOCKBYTES };

    const POLY_UNIFORM_ETA_NBLOCKS: usize = if ETA == 2 {
        (136 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES
    } else {
        (227 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES
    };

    let mut ctr;
    let buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM128_BLOCKBYTES;
    let mut buf = vec![0u8; buflen];
    let mut state = crate::symmetric::Stream128State::default();

    stream128_init(&mut state, seed, nonce);
    stream128_squeezeblocks(&mut buf, POLY_UNIFORM_ETA_NBLOCKS, &mut state);

    ctr = rej_eta(a, N, &buf, buflen);

    while ctr < N {
        stream128_squeezeblocks(&mut buf, 1, &mut state);
        ctr += rej_eta(&mut a[ctr..], N - ctr, &buf, STREAM128_BLOCKBYTES);
    }
}
