use crate::params::{
    SEEDBYTES,
    CRHBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES,
    K,
    L,
    OMEGA,
    POLYW1_PACKEDBYTES,
    GAMMA1,
    GAMMA2,
    BETA,
};
use crate::packing::{ pack_pk, pack_sk, pack_sig, unpack_pk, unpack_sk, unpack_sig };
use crate::polyvec::{
    PolyVecL,
    PolyVecK,
    polyvec_matrix_expand,
    polyvecl_uniform_eta,
    polyveck_uniform_eta,
    polyvecl_ntt,
    polyvec_matrix_pointwise_montgomery,
    polyveck_reduce,
    polyveck_invntt_tomont,
    polyveck_add,
    polyveck_caddq,
    polyveck_power2round,
    polyvecl_uniform_gamma1,
    polyveck_decompose,
    polyveck_pack_w1,
    polyvecl_pointwise_poly_montgomery,
    polyvecl_invntt_tomont,
    polyvecl_add,
    polyvecl_reduce,
    polyvecl_chknorm,
    polyveck_pointwise_poly_montgomery,
    polyveck_sub,
    polyveck_chknorm,
    polyveck_make_hint,
    polyveck_shiftl,
    polyveck_use_hint,
    polyveck_ntt,
};
use crate::poly::{ Poly, poly_challenge, poly_ntt };
use crate::symmetric::{
    crh,
    shake256_init,
    shake256_absorb,
    shake256_finalize,
    shake256_squeeze,
    shake256,
    KeccakState,
};
use getrandom::getrandom;

// EXACT NIST reference implementation - no modifications

/*************************************************
 * Name:        crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - pk: pointer to output public key (allocated
 *                    array of CRYPTO_PUBLICKEYBYTES bytes)
 *              - sk: pointer to output private key (allocated
 *                    array of CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
pub fn crypto_sign_keypair(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES]
) -> i32 {
    let mut seedbuf = [0u8; 3 * SEEDBYTES];
    let mut tr = [0u8; CRHBYTES];
    let mut mat = [PolyVecL::default(); K];
    let mut s1 = PolyVecL::default();
    let mut s1hat = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    let mut t1 = PolyVecK::default();
    let mut t0 = PolyVecK::default();

    /* Get randomness for rho, rhoprime and key */
    getrandom(&mut seedbuf[..SEEDBYTES]).unwrap();
    let mut temp_seedbuf = seedbuf;
    shake256(&mut temp_seedbuf, &seedbuf[..SEEDBYTES]);
    seedbuf = temp_seedbuf;
    let rho: &[u8; SEEDBYTES] = &seedbuf[..SEEDBYTES].try_into().unwrap();
    let rhoprime: &[u8; SEEDBYTES] = &seedbuf[SEEDBYTES..2 * SEEDBYTES].try_into().unwrap();
    let key: &[u8; SEEDBYTES] = &seedbuf[2 * SEEDBYTES..3 * SEEDBYTES].try_into().unwrap();

    /* Expand matrix */
    polyvec_matrix_expand(&mut mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta(&mut s1, rhoprime, 0);
    polyveck_uniform_eta(&mut s2, rhoprime, L.try_into().unwrap());

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(&mut s1hat);
    polyvec_matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
    polyveck_reduce(&mut t1);
    polyveck_invntt_tomont(&mut t1);

    /* Add error vector s2 */
    let t1_copy = t1;
    polyveck_add(&mut t1, &t1_copy, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq(&mut t1);
    let mut t1_copy = t1;
    polyveck_power2round(&mut t1_copy, &mut t0, &t1);
    pack_pk(pk, rho, &t1_copy);

    /* Compute CRH(rho, t1) and write secret key */
    crh(&mut tr, pk);
    pack_sk(sk, rho, &tr, key, &t0, &s1, &s2);

    0
}

/*************************************************
 * Name:        crypto_sign_signature
 *
 * Description: Computes signature.
 *
 * Arguments:   - sig: pointer to output signature (of length CRYPTO_BYTES)
 *              - siglen: pointer to output length of signature
 *              - m: pointer to message to be signed
 *              - mlen: length of message
 *              - sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
pub fn crypto_sign_signature(
    sig: &mut [u8; CRYPTO_BYTES],
    siglen: &mut usize,
    m: &[u8],
    mlen: usize,
    sk: &[u8; CRYPTO_SECRETKEYBYTES]
) -> i32 {
    let mut seedbuf = [0u8; 2 * SEEDBYTES + 3 * CRHBYTES];
    let mut nonce = 0u16;
    let mut mat = [PolyVecL::default(); K];
    let mut s1 = PolyVecL::default();
    let mut y = PolyVecL::default();
    let mut z = PolyVecL::default();
    let mut t0 = PolyVecK::default();
    let mut s2 = PolyVecK::default();
    let mut w1 = PolyVecK::default();
    let mut w0 = PolyVecK::default();
    let mut h = PolyVecK::default();
    let mut cp = Poly::default();
    let mut state = KeccakState::default();

    let (rho_part, rest1) = seedbuf.split_at_mut(SEEDBYTES);
    let (tr_part, rest2) = rest1.split_at_mut(CRHBYTES);
    let (key_part, rest3) = rest2.split_at_mut(SEEDBYTES);
    let (mu_part, rest4) = rest3.split_at_mut(CRHBYTES);
    let (rhoprime_part, _) = rest4.split_at_mut(CRHBYTES);

    unpack_sk(
        rho_part.try_into().unwrap(),
        tr_part.try_into().unwrap(),
        key_part.try_into().unwrap(),
        &mut t0,
        &mut s1,
        &mut s2,
        sk
    );

    /* Compute CRH(tr, msg) */
    shake256_init(&mut state);
    shake256_absorb(&mut state, tr_part);
    shake256_absorb(&mut state, m);
    shake256_finalize(&mut state);
    shake256_squeeze(mu_part, mu_part.len(), &mut state);

    #[cfg(not(feature = "randomized_signing"))]
    {
        let key_tr_combined = [key_part, tr_part].concat();
        crh(rhoprime_part.try_into().unwrap(), &key_tr_combined);
    }

    #[cfg(feature = "randomized_signing")]
    getrandom(rhoprime_part).unwrap();

    /* Expand matrix and transform vectors */
    let rho_array: [u8; SEEDBYTES] = rho_part.try_into().unwrap();
    polyvec_matrix_expand(&mut mat, &rho_array);
    polyvecl_ntt(&mut s1);
    polyveck_ntt(&mut s2);
    polyveck_ntt(&mut t0);

    'rej: loop {
        /* Sample intermediate vector y */
        let rhoprime_array: [u8; CRHBYTES] = rhoprime_part.try_into().unwrap();
        polyvecl_uniform_gamma1(&mut y, &rhoprime_array, nonce);
        nonce += 1;
        z = y;
        polyvecl_ntt(&mut z);

        /* Matrix-vector multiplication */
        polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
        polyveck_reduce(&mut w1);
        polyveck_invntt_tomont(&mut w1);

        /* Decompose w and call the random oracle */
        polyveck_caddq(&mut w1);
        let mut w1_copy = w1;
        polyveck_decompose(&mut w1_copy, &mut w0, &w1);
        w1 = w1_copy;
        let mut w1_buf = [0u8; K * POLYW1_PACKEDBYTES];
        polyveck_pack_w1(&mut w1_buf, &w1);

        shake256_init(&mut state);
        shake256_absorb(&mut state, mu_part);
        shake256_absorb(&mut state, &w1_buf);
        shake256_finalize(&mut state);
        shake256_squeeze(&mut sig[..SEEDBYTES], SEEDBYTES, &mut state);
        let sig_array: [u8; SEEDBYTES] = sig[..SEEDBYTES].try_into().unwrap();
        poly_challenge(&mut cp, &sig_array);
        poly_ntt(&mut cp);

        /* Compute z, reject if it reveals secret */
        polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
        polyvecl_invntt_tomont(&mut z);
        let mut z_copy = z;
        polyvecl_add(&mut z_copy, &z, &y);
        z = z_copy;
        polyvecl_reduce(&mut z);
        if polyvecl_chknorm(&z, (GAMMA1 - BETA).try_into().unwrap()) != 0 {
            continue 'rej;
        }

        /* Check that subtracting cs2 does not change high bits of w and low bits
         * do not reveal secret information */
        polyveck_pointwise_poly_montgomery(&mut h, &cp, &s2);
        polyveck_invntt_tomont(&mut h);
        let mut w0_copy = w0;
        polyveck_sub(&mut w0_copy, &w0, &h);
        w0 = w0_copy;
        polyveck_reduce(&mut w0);
        if polyveck_chknorm(&w0, (GAMMA2 - BETA).try_into().unwrap()) != 0 {
            continue 'rej;
        }

        /* Compute hints for w1 */
        polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
        polyveck_invntt_tomont(&mut h);
        polyveck_reduce(&mut h);
        if polyveck_chknorm(&h, GAMMA2.try_into().unwrap()) != 0 {
            continue 'rej;
        }

        let mut w0_copy = w0;
        polyveck_add(&mut w0_copy, &w0, &h);
        w0 = w0_copy;
        polyveck_caddq(&mut w0);
        let n = polyveck_make_hint(&mut h, &w0, &w1);
        if n > OMEGA {
            continue 'rej;
        }

        /* Write signature */
        pack_sig(sig, &sig_array, &z, &h);
        *siglen = CRYPTO_BYTES;
        return 0;
    }
}

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Compute signed message.
 *
 * Arguments:   - sm: pointer to output signed message (allocated
 *                    array with CRYPTO_BYTES + mlen bytes),
 *                    can be equal to m
 *              - smlen: pointer to output length of signed
 *                       message
 *              - m: pointer to message to be signed
 *              - mlen: length of message
 *              - sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
pub fn crypto_sign(
    sm: &mut [u8],
    smlen: &mut usize,
    m: &[u8],
    mlen: usize,
    sk: &[u8; CRYPTO_SECRETKEYBYTES]
) -> i32 {
    for i in 0..mlen {
        sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    let mut siglen = 0;
    crypto_sign_signature(
        &mut sm[..CRYPTO_BYTES].try_into().unwrap(),
        &mut siglen,
        &sm[CRYPTO_BYTES..CRYPTO_BYTES + mlen],
        mlen,
        sk
    );
    *smlen = siglen + mlen;
    0
}

/*************************************************
 * Name:        crypto_sign_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:   - sig: pointer to input signature
 *              - siglen: length of signature
 *              - m: pointer to message
 *              - mlen: length of message
 *              - pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
pub fn crypto_sign_verify(
    sig: &[u8],
    siglen: usize,
    m: &[u8],
    mlen: usize,
    pk: &[u8; CRYPTO_PUBLICKEYBYTES]
) -> i32 {
    let mut buf = [0u8; K * POLYW1_PACKEDBYTES];
    let mut rho = [0u8; SEEDBYTES];
    let mut mu = [0u8; CRHBYTES];
    let mut c = [0u8; SEEDBYTES];
    let mut c2 = [0u8; SEEDBYTES];
    let mut cp = Poly::default();
    let mut mat = [PolyVecL::default(); K];
    let mut z = PolyVecL::default();
    let mut t1 = PolyVecK::default();
    let mut w1 = PolyVecK::default();
    let mut h = PolyVecK::default();
    let mut state = KeccakState::default();

    if siglen != CRYPTO_BYTES {
        return -1;
    }

    unpack_pk(&mut rho, &mut t1, pk);
    if unpack_sig(&mut c, &mut z, &mut h, sig.try_into().unwrap()) != 0 {
        return -1;
    }
    if polyvecl_chknorm(&z, (GAMMA1 - BETA).try_into().unwrap()) != 0 {
        return -1;
    }

    /* Compute CRH(CRH(rho, t1), msg) */
    crh(&mut mu, pk);
    shake256_init(&mut state);
    shake256_absorb(&mut state, &mu);
    shake256_absorb(&mut state, m);
    shake256_finalize(&mut state);
    shake256_squeeze(&mut mu, CRHBYTES, &mut state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge(&mut cp, &c);
    polyvec_matrix_expand(&mut mat, &rho);

    polyvecl_ntt(&mut z);
    polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);

    poly_ntt(&mut cp);
    polyveck_shiftl(&mut t1);
    polyveck_ntt(&mut t1);
    let mut t1_copy = t1;
    polyveck_pointwise_poly_montgomery(&mut t1_copy, &cp, &t1);
    t1 = t1_copy;

    let mut w1_copy = w1;
    polyveck_sub(&mut w1_copy, &w1, &t1);
    w1 = w1_copy;
    polyveck_reduce(&mut w1);
    polyveck_invntt_tomont(&mut w1);

    /* Reconstruct w1 */
    polyveck_caddq(&mut w1);
    let mut w1_copy2 = w1;
    polyveck_use_hint(&mut w1_copy2, &w1, &h);
    w1 = w1_copy2;
    polyveck_pack_w1(&mut buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_init(&mut state);
    shake256_absorb(&mut state, &mu);
    shake256_absorb(&mut state, &buf);
    shake256_finalize(&mut state);
    shake256_squeeze(&mut c2, SEEDBYTES, &mut state);
    for i in 0..SEEDBYTES {
        if c[i] != c2[i] {
            return -1;
        }
    }

    0
}

/*************************************************
 * Name:        crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - m: pointer to output message (allocated
 *                   array with smlen bytes), can be equal to sm
 *              - mlen: pointer to output length of message
 *              - sm: pointer to signed message
 *              - smlen: length of signed message
 *              - pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
pub fn crypto_sign_open(
    m: &mut [u8],
    mlen: &mut usize,
    sm: &[u8],
    smlen: usize,
    pk: &[u8; CRYPTO_PUBLICKEYBYTES]
) -> i32 {
    if smlen < CRYPTO_BYTES {
        goto_badsig(m, smlen, mlen);
        return -1;
    }

    *mlen = smlen - CRYPTO_BYTES;
    if crypto_sign_verify(&sm[..CRYPTO_BYTES], CRYPTO_BYTES, &sm[CRYPTO_BYTES..], *mlen, pk) != 0 {
        goto_badsig(m, smlen, mlen);
        return -1;
    } else {
        /* All good, copy msg, return 0 */
        for i in 0..*mlen {
            m[i] = sm[CRYPTO_BYTES + i];
        }
        return 0;
    }
}

fn goto_badsig(m: &mut [u8], smlen: usize, mlen: &mut usize) {
    /* Signature verification failed */
    *mlen = usize::MAX;
    for i in 0..smlen {
        m[i] = 0;
    }
}
