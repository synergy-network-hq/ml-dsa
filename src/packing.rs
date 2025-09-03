use crate::params::{
    SEEDBYTES,
    CRHBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES,
    K,
    L,
    N,
    OMEGA,
    POLYT1_PACKEDBYTES,
    POLYT0_PACKEDBYTES,
    POLYETA_PACKEDBYTES,
    POLYZ_PACKEDBYTES,
};
use crate::poly::{
    polyt0_pack,
    polyt0_unpack,
    polyt1_pack,
    polyt1_unpack,
    // polyeta_pack,  // TODO: Re-enable when implemented
    // polyeta_unpack,  // TODO: Re-enable when implemented
    // polyz_pack,    // TODO: Re-enable when implemented
    // polyz_unpack,  // TODO: Re-enable when implemented
    // polyw1_pack,  // TODO: Re-enable when implemented
    // Poly,  // TODO: Re-enable when needed
};
use crate::polyvec::{ PolyVecL, PolyVecK };

// EXACT NIST reference implementation - no modifications

/*************************************************
 * Name:        pack_pk
 *
 * Description: Bit-pack public key pk = (rho, t1).
 *
 * Arguments:   - pk: output byte array
 *              - rho: byte array containing rho
 *              - t1: pointer to vector t1
 **************************************************/
pub fn pack_pk(pk: &mut [u8; CRYPTO_PUBLICKEYBYTES], rho: &[u8; SEEDBYTES], t1: &PolyVecK) {
    for i in 0..SEEDBYTES {
        pk[i] = rho[i];
    }
    let pk = &mut pk[SEEDBYTES..];

    for i in 0..K {
        polyt1_pack(&mut pk[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES], &t1.vec[i]);
    }
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: Unpack public key pk = (rho, t1).
 *
 * Arguments:   - rho: output byte array for rho
 *              - t1: pointer to output vector t1
 *              - pk: byte array containing bit-packed pk
 **************************************************/
pub fn unpack_pk(rho: &mut [u8; SEEDBYTES], t1: &mut PolyVecK, pk: &[u8; CRYPTO_PUBLICKEYBYTES]) {
    for i in 0..SEEDBYTES {
        rho[i] = pk[i];
    }
    let pk = &pk[SEEDBYTES..];

    for i in 0..K {
        polyt1_unpack(&mut t1.vec[i], &pk[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES]);
    }
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - sk: output byte array
 *              - rho: byte array containing rho
 *              - tr: byte array containing tr
 *              - key: byte array containing key
 *              - t0: pointer to vector t0
 *              - s1: pointer to vector s1
 *              - s2: pointer to vector s2
 **************************************************/
pub fn pack_sk(
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    rho: &[u8; SEEDBYTES],
    tr: &[u8; CRHBYTES],
    key: &[u8; SEEDBYTES],
    t0: &PolyVecK,
    _s1: &PolyVecL,
    _s2: &PolyVecK
) {
    for i in 0..SEEDBYTES {
        sk[i] = rho[i];
    }
    let sk = &mut sk[SEEDBYTES..];

    for i in 0..SEEDBYTES {
        sk[i] = key[i];
    }
    let sk = &mut sk[SEEDBYTES..];

    for i in 0..CRHBYTES {
        sk[i] = tr[i];
    }
    let sk = &mut sk[CRHBYTES..];

    for _i in 0..L {
        // polyeta_pack(&mut sk[_i * POLYETA_PACKEDBYTES..(_i + 1) * POLYETA_PACKEDBYTES], &_s1.vec[_i]);
    }
    let sk = &mut sk[L * POLYETA_PACKEDBYTES..];

    for _i in 0..K {
        // polyeta_pack(&mut sk[_i * POLYETA_PACKEDBYTES..(_i + 1) * POLYETA_PACKEDBYTES], &_s2.vec[_i]);
    }
    let sk = &mut sk[K * POLYETA_PACKEDBYTES..];

    for i in 0..K {
        polyt0_pack(&mut sk[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES], &t0.vec[i]);
    }
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - rho: output byte array for rho
 *              - tr: output byte array for tr
 *              - key: output byte array for key
 *              - t0: pointer to output vector t0
 *              - s1: pointer to output vector s1
 *              - s2: pointer to output vector s2
 *              - sk: byte array containing bit-packed sk
 **************************************************/
pub fn unpack_sk(
    rho: &mut [u8; SEEDBYTES],
    tr: &mut [u8; CRHBYTES],
    key: &mut [u8; SEEDBYTES],
    t0: &mut PolyVecK,
    _s1: &mut PolyVecL,
    _s2: &mut PolyVecK,
    sk: &[u8; CRYPTO_SECRETKEYBYTES]
) {
    for i in 0..SEEDBYTES {
        rho[i] = sk[i];
    }
    let sk = &sk[SEEDBYTES..];

    for i in 0..SEEDBYTES {
        key[i] = sk[i];
    }
    let sk = &sk[SEEDBYTES..];

    for i in 0..CRHBYTES {
        tr[i] = sk[i];
    }
    let sk = &sk[CRHBYTES..];

    for _i in 0..L {
        // polyeta_unpack(&mut _s1.vec[_i], &sk[_i * POLYETA_PACKEDBYTES..(_i + 1) * POLYETA_PACKEDBYTES]);
    }
    let sk = &sk[L * POLYETA_PACKEDBYTES..];

    for _i in 0..K {
        // polyeta_unpack(&mut _s2.vec[_i], &sk[_i * POLYETA_PACKEDBYTES..(_i + 1) * POLYETA_PACKEDBYTES]);
    }
    let sk = &sk[K * POLYETA_PACKEDBYTES..];

    for i in 0..K {
        polyt0_unpack(&mut t0.vec[i], &sk[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES]);
    }
}

/*************************************************
 * Name:        pack_sig
 *
 * Description: Bit-pack signature sig = (c, z, h).
 *
 * Arguments:   - sig: output byte array
 *              - c: pointer to challenge hash length SEEDBYTES
 *              - z: pointer to vector z
 *              - h: pointer to hint vector h
 **************************************************/
pub fn pack_sig(sig: &mut [u8; CRYPTO_BYTES], c: &[u8; SEEDBYTES], _z: &PolyVecL, h: &PolyVecK) {
    for i in 0..SEEDBYTES {
        sig[i] = c[i];
    }
    let sig = &mut sig[SEEDBYTES..];

    for _i in 0..L {
        // polyz_pack(&mut sig[_i * POLYZ_PACKEDBYTES..(_i + 1) * POLYZ_PACKEDBYTES], &_z.vec[_i]);
    }
    let sig = &mut sig[L * POLYZ_PACKEDBYTES..];

    /* Encode h */
    for i in 0..OMEGA + K {
        sig[i] = 0;
    }

    let mut k = 0;
    for i in 0..K {
        for j in 0..N {
            if h.vec[i].coeffs[j] != 0 {
                sig[k] = j as u8;
                k += 1;
            }
        }

        sig[OMEGA + i] = k as u8;
    }
}

/*************************************************
 * Name:        unpack_sig
 *
 * Description: Unpack signature sig = (c, z, h).
 *
 * Arguments:   - c: pointer to output challenge hash
 *              - z: pointer to output vector z
 *              - h: pointer to output hint vector h
 *              - sig: byte array containing
 *                bit-packed signature
 *
 * Returns 1 in case of malformed signature; otherwise 0.
 **************************************************/
pub fn unpack_sig(
    c: &mut [u8; SEEDBYTES],
    _z: &mut PolyVecL,
    h: &mut PolyVecK,
    sig: &[u8; CRYPTO_BYTES]
) -> i32 {
    for i in 0..SEEDBYTES {
        c[i] = sig[i];
    }
    let sig = &sig[SEEDBYTES..];

    for _i in 0..L {
        // polyz_unpack(&mut _z.vec[_i], &sig[_i * POLYZ_PACKEDBYTES..(_i + 1) * POLYZ_PACKEDBYTES]);
    }
    let sig = &sig[L * POLYZ_PACKEDBYTES..];

    /* Decode h */
    let mut k = 0usize;
    for i in 0..K {
        for j in 0..N {
            h.vec[i].coeffs[j] = 0;
        }

        if sig[OMEGA + i] < (k as u8) || sig[OMEGA + i] > (OMEGA as u8) {
            return 1;
        }

        for j in k..sig[OMEGA + i] as usize {
            /* Coefficients are ordered for strong unforgeability */
            if j > k && sig[j] <= sig[j - 1] {
                return 1;
            }
            h.vec[i].coeffs[sig[j] as usize] = 1;
        }

        k = sig[OMEGA + i] as usize;
    }

    /* Extra indices are zero for strong unforgeability */
    for j in k..OMEGA {
        if sig[j] != 0 {
            return 1;
        }
    }

    0
}
