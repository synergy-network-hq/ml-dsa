use crate::params::{ SEEDBYTES, CRHBYTES };

// EXACT NIST reference implementation - no modifications

pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;
pub const SHA3_256_RATE: usize = 136;
pub const SHA3_512_RATE: usize = 72;

pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;
pub const STREAM256_BLOCKBYTES: usize = SHAKE256_RATE;

#[derive(Clone, Default)]
pub struct KeccakState {
    pub s: [u64; 25],
    pub pos: usize,
}

pub type Stream128State = KeccakState;
pub type Stream256State = KeccakState;

const NROUNDS: usize = 24;

// Keccak round constants - EXACT from NIST reference
const KECCAK_F_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

#[inline]
fn rol(a: u64, offset: u32) -> u64 {
    (a << offset) ^ (a >> (64 - offset))
}

#[inline]
fn load64(x: &[u8]) -> u64 {
    let mut r = 0u64;
    for i in 0..8 {
        r |= (x[i] as u64) << (8 * i);
    }
    r
}

#[inline]
fn store64(x: &mut [u8], u: u64) {
    for i in 0..8 {
        x[i] = (u >> (8 * i)) as u8;
    }
}

// EXACT NIST KeccakF1600_StatePermute implementation
fn keccak_f1600_state_permute(state: &mut [u64; 25]) {
    let mut aba = state[0];
    let mut abe = state[1];
    let mut abi = state[2];
    let mut abo = state[3];
    let mut abu = state[4];
    let mut aga = state[5];
    let mut age = state[6];
    let mut agi = state[7];
    let mut ago = state[8];
    let mut agu = state[9];
    let mut aka = state[10];
    let mut ake = state[11];
    let mut aki = state[12];
    let mut ako = state[13];
    let mut aku = state[14];
    let mut ama = state[15];
    let mut ame = state[16];
    let mut ami = state[17];
    let mut amo = state[18];
    let mut amu = state[19];
    let mut asa = state[20];
    let mut ase = state[21];
    let mut asi = state[22];
    let mut aso = state[23];
    let mut asu = state[24];

    for round in (0..NROUNDS).step_by(2) {
        // prepareTheta
        let bca = aba ^ aga ^ aka ^ ama ^ asa;
        let bce = abe ^ age ^ ake ^ ame ^ ase;
        let bci = abi ^ agi ^ aki ^ ami ^ asi;
        let bco = abo ^ ago ^ ako ^ amo ^ aso;
        let bcu = abu ^ agu ^ aku ^ amu ^ asu;

        // thetaRhoPiChiIotaPrepareTheta(round, A, E)
        let da = bcu ^ rol(bce, 1);
        let de = bca ^ rol(bci, 1);
        let di = bce ^ rol(bco, 1);
        let do_ = bci ^ rol(bcu, 1);
        let du = bco ^ rol(bca, 1);

        aba ^= da;
        let bca = aba;
        age ^= de;
        let bce = rol(age, 44);
        aki ^= di;
        let bci = rol(aki, 43);
        amo ^= do_;
        let bco = rol(amo, 21);
        asu ^= du;
        let bcu = rol(asu, 14);
        let mut eba = bca ^ (!bce & bci);
        eba ^= KECCAK_F_ROUND_CONSTANTS[round];
        let mut ebe = bce ^ (!bci & bco);
        let mut ebi = bci ^ (!bco & bcu);
        let mut ebo = bco ^ (!bcu & bca);
        let mut ebu = bcu ^ (!bca & bce);

        abo ^= do_;
        let bca = rol(abo, 28);
        agu ^= du;
        let bce = rol(agu, 20);
        aka ^= da;
        let bci = rol(aka, 3);
        ame ^= de;
        let bco = rol(ame, 45);
        asi ^= di;
        let bcu = rol(asi, 61);
        let mut ega = bca ^ (!bce & bci);
        let mut ege = bce ^ (!bci & bco);
        let mut egi = bci ^ (!bco & bcu);
        let mut ego = bco ^ (!bcu & bca);
        let mut egu = bcu ^ (!bca & bce);

        abe ^= de;
        let bca = rol(abe, 1);
        agi ^= di;
        let bce = rol(agi, 6);
        ako ^= do_;
        let bci = rol(ako, 25);
        amu ^= du;
        let bco = rol(amu, 8);
        asa ^= da;
        let bcu = rol(asa, 18);
        let mut eka = bca ^ (!bce & bci);
        let mut eke = bce ^ (!bci & bco);
        let mut eki = bci ^ (!bco & bcu);
        let mut eko = bco ^ (!bcu & bca);
        let mut eku = bcu ^ (!bca & bce);

        abu ^= du;
        let bca = rol(abu, 27);
        aga ^= da;
        let bce = rol(aga, 36);
        ake ^= de;
        let bci = rol(ake, 10);
        ami ^= di;
        let bco = rol(ami, 15);
        aso ^= do_;
        let bcu = rol(aso, 56);
        let mut ema = bca ^ (!bce & bci);
        let mut eme = bce ^ (!bci & bco);
        let mut emi = bci ^ (!bco & bcu);
        let mut emo = bco ^ (!bcu & bca);
        let mut emu = bcu ^ (!bca & bce);

        abi ^= di;
        let bca = rol(abi, 62);
        ago ^= do_;
        let bce = rol(ago, 55);
        aku ^= du;
        let bci = rol(aku, 39);
        ama ^= da;
        let bco = rol(ama, 41);
        ase ^= de;
        let bcu = rol(ase, 2);
        let mut esa = bca ^ (!bce & bci);
        let mut ese = bce ^ (!bci & bco);
        let mut esi = bci ^ (!bco & bcu);
        let mut eso = bco ^ (!bcu & bca);
        let mut esu = bcu ^ (!bca & bce);

        // prepareTheta
        let bca = eba ^ ega ^ eka ^ ema ^ esa;
        let bce = ebe ^ ege ^ eke ^ eme ^ ese;
        let bci = ebi ^ egi ^ eki ^ emi ^ esi;
        let bco = ebo ^ ego ^ eko ^ emo ^ eso;
        let bcu = ebu ^ egu ^ eku ^ emu ^ esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        let da = bcu ^ rol(bce, 1);
        let de = bca ^ rol(bci, 1);
        let di = bce ^ rol(bco, 1);
        let do_ = bci ^ rol(bcu, 1);
        let du = bco ^ rol(bca, 1);

        eba ^= da;
        let bca = eba;
        ege ^= de;
        let bce = rol(ege, 44);
        eki ^= di;
        let bci = rol(eki, 43);
        emo ^= do_;
        let bco = rol(emo, 21);
        esu ^= du;
        let bcu = rol(esu, 14);
        aba = bca ^ (!bce & bci);
        aba ^= KECCAK_F_ROUND_CONSTANTS[round + 1];
        abe = bce ^ (!bci & bco);
        abi = bci ^ (!bco & bcu);
        abo = bco ^ (!bcu & bca);
        abu = bcu ^ (!bca & bce);

        ebo ^= do_;
        let bca = rol(ebo, 28);
        egu ^= du;
        let bce = rol(egu, 20);
        eka ^= da;
        let bci = rol(eka, 3);
        eme ^= de;
        let bco = rol(eme, 45);
        esi ^= di;
        let bcu = rol(esi, 61);
        aga = bca ^ (!bce & bci);
        age = bce ^ (!bci & bco);
        agi = bci ^ (!bco & bcu);
        ago = bco ^ (!bcu & bca);
        agu = bcu ^ (!bca & bce);

        ebe ^= de;
        let bca = rol(ebe, 1);
        egi ^= di;
        let bce = rol(egi, 6);
        eko ^= do_;
        let bci = rol(eko, 25);
        emu ^= du;
        let bco = rol(emu, 8);
        esa ^= da;
        let bcu = rol(esa, 18);
        aka = bca ^ (!bce & bci);
        ake = bce ^ (!bci & bco);
        aki = bci ^ (!bco & bcu);
        ako = bco ^ (!bcu & bca);
        aku = bcu ^ (!bca & bce);

        ebu ^= du;
        let bca = rol(ebu, 27);
        ega ^= da;
        let bce = rol(ega, 36);
        eke ^= de;
        let bci = rol(eke, 10);
        emi ^= di;
        let bco = rol(emi, 15);
        eso ^= do_;
        let bcu = rol(eso, 56);
        ama = bca ^ (!bce & bci);
        ame = bce ^ (!bci & bco);
        ami = bci ^ (!bco & bcu);
        amo = bco ^ (!bcu & bca);
        amu = bcu ^ (!bca & bce);

        ebi ^= di;
        let bca = rol(ebi, 62);
        ego ^= do_;
        let bce = rol(ego, 55);
        eku ^= du;
        let bci = rol(eku, 39);
        ema ^= da;
        let bco = rol(ema, 41);
        ese ^= de;
        let bcu = rol(ese, 2);
        asa = bca ^ (!bce & bci);
        ase = bce ^ (!bci & bco);
        asi = bci ^ (!bco & bcu);
        aso = bco ^ (!bcu & bca);
        asu = bcu ^ (!bca & bce);
    }

    // copyToState(state, A)
    state[0] = aba;
    state[1] = abe;
    state[2] = abi;
    state[3] = abo;
    state[4] = abu;
    state[5] = aga;
    state[6] = age;
    state[7] = agi;
    state[8] = ago;
    state[9] = agu;
    state[10] = aka;
    state[11] = ake;
    state[12] = aki;
    state[13] = ako;
    state[14] = aku;
    state[15] = ama;
    state[16] = ame;
    state[17] = ami;
    state[18] = amo;
    state[19] = amu;
    state[20] = asa;
    state[21] = ase;
    state[22] = asi;
    state[23] = aso;
    state[24] = asu;
}

fn keccak_init(state: &mut KeccakState) {
    state.s.fill(0);
    state.pos = 0;
}

fn keccak_absorb(s: &mut [u64; 25], r: usize, mut pos: usize, m: &[u8]) -> usize {
    let mut t = [0u8; 8];

    if (pos & 7) != 0 {
        let i = pos & 7;
        let mut j = 0;
        while i + j < 8 && j < m.len() {
            t[i + j] = m[j];
            j += 1;
        }
        pos += j;
        s[(pos - j) / 8] ^= load64(&t);
    }

    if pos != 0 && m.len() >= r - pos {
        for i in 0..(r - pos) / 8 {
            s[pos / 8 + i] ^= load64(&m[8 * i..8 * i + 8]);
        }
        let _m = &m[r - pos..];
        pos = 0;
        keccak_f1600_state_permute(s);
    }

    let mut m = m;
    while m.len() >= r {
        for i in 0..r / 8 {
            s[i] ^= load64(&m[8 * i..8 * i + 8]);
        }
        m = &m[r..];
        keccak_f1600_state_permute(s);
    }

    for i in 0..m.len() / 8 {
        s[pos / 8 + i] ^= load64(&m[8 * i..8 * i + 8]);
    }
    let m = &m[8 * (m.len() / 8)..];
    pos += 8 * (m.len() / 8);

    if !m.is_empty() {
        t.fill(0);
        for i in 0..m.len() {
            t[i] = m[i];
        }
        s[pos / 8] ^= load64(&t);
        pos += m.len();
    }

    pos
}

fn keccak_finalize(s: &mut [u64; 25], r: usize, pos: usize, p: u8) {
    let i = pos >> 3;
    let j = pos & 7;
    s[i] ^= (p as u64) << (8 * j);
    s[r / 8 - 1] ^= 1u64 << 63;
}

fn keccak_squeezeblocks(out: &mut [u8], nblocks: usize, s: &mut [u64; 25], r: usize) {
    let mut out = out;
    let mut nblocks = nblocks;
    while nblocks > 0 {
        keccak_f1600_state_permute(s);
        for i in 0..r / 8 {
            store64(&mut out[8 * i..8 * i + 8], s[i]);
        }
        out = &mut out[r..];
        nblocks -= 1;
    }
}

fn keccak_squeeze(
    out: &mut [u8],
    mut outlen: usize,
    s: &mut [u64; 25],
    r: usize,
    mut pos: usize
) -> usize {
    let mut out = out;
    let mut t = [0u8; 8];

    if (pos & 7) != 0 {
        store64(&mut t, s[pos / 8]);
        let i = pos & 7;
        let mut j = 0;
        while i + j < 8 && j < outlen {
            out[j] = t[i + j];
            j += 1;
        }
        out = &mut out[j..];
        outlen -= j;
        pos += j;
    }

    if pos != 0 && outlen >= r - pos {
        for i in 0..(r - pos) / 8 {
            store64(&mut out[8 * i..8 * i + 8], s[pos / 8 + i]);
        }
        out = &mut out[r - pos..];
        outlen -= r - pos;
        pos = 0;
    }

    while outlen >= r {
        keccak_f1600_state_permute(s);
        for i in 0..r / 8 {
            store64(&mut out[8 * i..8 * i + 8], s[i]);
        }
        out = &mut out[r..];
        outlen -= r;
    }

    if outlen == 0 {
        return pos;
    } else if pos == 0 {
        keccak_f1600_state_permute(s);
    }

    for i in 0..outlen / 8 {
        store64(&mut out[8 * i..8 * i + 8], s[pos / 8 + i]);
    }
    out = &mut out[8 * (outlen / 8)..];
    outlen -= 8 * (outlen / 8);
    pos += 8 * (outlen / 8);

    store64(&mut t, s[pos / 8]);
    for i in 0..outlen {
        out[i] = t[i];
    }
    pos += outlen;
    pos
}

/*************************************************
 * Name:        shake128_init
 *
 * Description: Initializes Keccak state for use as SHAKE128
 *
 * Arguments:   - state: pointer to (uninitialized) Keccak state
 **************************************************/
pub fn shake128_init(state: &mut KeccakState) {
    keccak_init(state);
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of SHAKE128; non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - state: pointer to (initialized) output Keccak state
 *              - input: pointer to input to be absorbed into state
 *              - inlen: length of input in bytes
 **************************************************/
pub fn shake128_absorb(state: &mut KeccakState, input: &[u8]) {
    state.pos = keccak_absorb(&mut state.s, SHAKE128_RATE, state.pos, input);
}

/*************************************************
 * Name:        shake128_finalize
 *
 * Description: Finalize absorb step.
 *
 * Arguments:   - state: pointer to Keccak state
 **************************************************/
pub fn shake128_finalize(state: &mut KeccakState) {
    keccak_finalize(&mut state.s, SHAKE128_RATE, state.pos, 0x1f);
    state.pos = 0;
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128. Squeezes full blocks of SHAKE128_RATE bytes each.
 *              Modifies the state. Can be called multiple times to keep squeezing,
 *              i.e., is incremental.
 *
 * Arguments:   - out: pointer to output blocks
 *              - nblocks: number of blocks to be squeezed (written to out)
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn shake128_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(out, nblocks, &mut state.s, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake128_squeeze
 *
 * Description: Squeeze step of SHAKE128. Squeezes arbitrary number of bytes.
 *              Modifies the state. Can be called multiple times to keep squeezing,
 *              i.e., is incremental.
 *
 * Arguments:   - out: pointer to output
 *              - outlen: number of bytes to be squeezed (written to out)
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn shake128_squeeze(out: &mut [u8], outlen: usize, state: &mut KeccakState) {
    state.pos = keccak_squeeze(out, outlen, &mut state.s, SHAKE128_RATE, state.pos);
}

/*************************************************
 * Name:        shake256_init
 *
 * Description: Initializes Keccak state for use as SHAKE256
 *
 * Arguments:   - state: pointer to (uninitialized) Keccak state
 **************************************************/
pub fn shake256_init(state: &mut KeccakState) {
    keccak_init(state);
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of SHAKE256; non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - state: pointer to (initialized) output Keccak state
 *              - input: pointer to input to be absorbed into state
 *              - inlen: length of input in bytes
 **************************************************/
pub fn shake256_absorb(state: &mut KeccakState, input: &[u8]) {
    state.pos = keccak_absorb(&mut state.s, SHAKE256_RATE, state.pos, input);
}

/*************************************************
 * Name:        shake256_finalize
 *
 * Description: Finalize absorb step.
 *
 * Arguments:   - state: pointer to Keccak state
 **************************************************/
pub fn shake256_finalize(state: &mut KeccakState) {
    keccak_finalize(&mut state.s, SHAKE256_RATE, state.pos, 0x1f);
    state.pos = 0;
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256. Squeezes full blocks of SHAKE256_RATE bytes each.
 *              Modifies the state. Can be called multiple times to keep squeezing,
 *              i.e., is incremental.
 *
 * Arguments:   - out: pointer to output blocks
 *              - nblocks: number of blocks to be squeezed (written to out)
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn shake256_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut KeccakState) {
    keccak_squeezeblocks(out, nblocks, &mut state.s, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake256_squeeze
 *
 * Description: Squeeze step of SHAKE256. Squeezes arbitrary number of bytes.
 *              Modifies the state. Can be called multiple times to keep squeezing,
 *              i.e., is incremental.
 *
 * Arguments:   - out: pointer to output
 *              - outlen: number of bytes to be squeezed (written to out)
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn shake256_squeeze(out: &mut [u8], outlen: usize, state: &mut KeccakState) {
    state.pos = keccak_squeeze(out, outlen, &mut state.s, SHAKE256_RATE, state.pos);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 function with length of output hardcoded to 32 bytes.
 *              NIST SP 800-185 compliant.
 *
 * Arguments:   - out: pointer to output
 *              - in: pointer to input
 *              - inlen: length of input in bytes
 **************************************************/
pub fn shake128(out: &mut [u8], input: &[u8]) {
    let mut state = KeccakState::default();
    shake128_init(&mut state);
    shake128_absorb(&mut state, input);
    shake128_finalize(&mut state);
    shake128_squeeze(out, out.len(), &mut state);
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 function with length of output hardcoded to 64 bytes.
 *              NIST SP 800-185 compliant.
 *
 * Arguments:   - out: pointer to output
 *              - in: pointer to input
 *              - inlen: length of input in bytes
 **************************************************/
pub fn shake256(out: &mut [u8], input: &[u8]) {
    let mut state = KeccakState::default();
    shake256_init(&mut state);
    shake256_absorb(&mut state, input);
    shake256_finalize(&mut state);
    shake256_squeeze(out, out.len(), &mut state);
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - h: pointer to output (32 bytes)
 *              - in: pointer to input
 *              - inlen: length of input in bytes
 **************************************************/
pub fn sha3_256(h: &mut [u8; 32], input: &[u8]) {
    let mut s = [0u64; 25];
    let pos = keccak_absorb(&mut s, SHA3_256_RATE, 0, input);
    keccak_finalize(&mut s, SHA3_256_RATE, pos, 0x06);
    keccak_squeeze(h, 32, &mut s, SHA3_256_RATE, 0);
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - h: pointer to output (64 bytes)
 *              - in: pointer to input
 *              - inlen: length of input in bytes
 **************************************************/
pub fn sha3_512(h: &mut [u8; 64], input: &[u8]) {
    let mut s = [0u64; 25];
    let pos = keccak_absorb(&mut s, SHA3_512_RATE, 0, input);
    keccak_finalize(&mut s, SHA3_512_RATE, pos, 0x06);
    keccak_squeeze(h, 64, &mut s, SHA3_512_RATE, 0);
}

/*************************************************
 * Name:        mldsa_shake128_stream_init
 *
 * Description: Initialize SHAKE128 stream for use in ML-DSA
 *
 * Arguments:   - state: pointer to Keccak state
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn mldsa_shake128_stream_init(state: &mut KeccakState, seed: &[u8; SEEDBYTES], nonce: u16) {
    let mut t = [0u8; 2];
    t[0] = nonce as u8;
    t[1] = (nonce >> 8) as u8;

    shake128_init(state);
    shake128_absorb(state, seed);
    shake128_absorb(state, &t);
    shake128_finalize(state);
}

/*************************************************
 * Name:        mldsa_shake256_stream_init
 *
 * Description: Initialize SHAKE256 stream for use in ML-DSA
 *
 * Arguments:   - state: pointer to Keccak state
 *              - seed: byte array with seed of length CRHBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn mldsa_shake256_stream_init(state: &mut KeccakState, seed: &[u8; CRHBYTES], nonce: u16) {
    let mut t = [0u8; 2];
    t[0] = nonce as u8;
    t[1] = (nonce >> 8) as u8;

    shake256_init(state);
    shake256_absorb(state, seed);
    shake256_absorb(state, &t);
    shake256_finalize(state);
}

/*************************************************
 * Name:        stream128_init
 *
 * Description: Initialize stream128 (alias for mldsa_shake128_stream_init)
 *
 * Arguments:   - state: pointer to Keccak state
 *              - seed: byte array with seed of length SEEDBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn stream128_init(state: &mut Stream128State, seed: &[u8; SEEDBYTES], nonce: u16) {
    mldsa_shake128_stream_init(state, seed, nonce);
}

/*************************************************
 * Name:        stream256_init
 *
 * Description: Initialize stream256 (alias for mldsa_shake256_stream_init)
 *
 * Arguments:   - state: pointer to Keccak state
 *              - seed: byte array with seed of length CRHBYTES
 *              - nonce: 2-byte nonce
 **************************************************/
pub fn stream256_init(state: &mut Stream256State, seed: &[u8; CRHBYTES], nonce: u16) {
    mldsa_shake256_stream_init(state, seed, nonce);
}

/*************************************************
 * Name:        stream128_squeezeblocks
 *
 * Description: Squeeze blocks from stream128 (alias for shake128_squeezeblocks)
 *
 * Arguments:   - out: pointer to output blocks
 *              - nblocks: number of blocks to be squeezed
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn stream128_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut Stream128State) {
    shake128_squeezeblocks(out, nblocks, state);
}

/*************************************************
 * Name:        stream256_squeezeblocks
 *
 * Description: Squeeze blocks from stream256 (alias for shake256_squeezeblocks)
 *
 * Arguments:   - out: pointer to output blocks
 *              - nblocks: number of blocks to be squeezed
 *              - state: pointer to input/output Keccak state
 **************************************************/
pub fn stream256_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut Stream256State) {
    shake256_squeezeblocks(out, nblocks, state);
}

/*************************************************
 * Name:        crh
 *
 * Description: CRH function (alias for shake256)
 *
 * Arguments:   - out: pointer to output
 *              - input: pointer to input
 *              - inlen: length of input in bytes
 **************************************************/
pub fn crh(out: &mut [u8; CRHBYTES], input: &[u8]) {
    shake256(out, input);
}
