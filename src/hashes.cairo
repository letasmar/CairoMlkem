// mod keccak;
use crate::opt_math::{OptBitShift, OptWrapping};
use core::num::traits::{Bounded, WrappingAdd};
use core::traits::{BitAnd, BitOr, BitXor, BitNot};

const SHA3_256_RATE_BYTES: usize = 136;
const SHA3_256_DOMAIN: u8 = 0x06;
const SHA3_256_OUTLEN: usize = 32;
const SHA3_512_RATE_BYTES: usize = 72;
const SHA3_512_DOMAIN: u8 = 0x06;
const SHA3_512_OUTLEN: usize = 64;

const SHAKE128_RATE_BYTES: usize = 168;
const SHAKE128_DOMAIN: u8 = 0x1F;
const SHAKE256_RATE_BYTES: usize = 136;
const SHAKE256_DOMAIN: u8 = 0x1F;

// ---------- Constants for keccak ----------
const LANES: usize = 25;
const LANE_BYTES: u64 = 8; // 64 bits
const KECCAK_ROUNDS: usize = 24;

// use keccak::keccak_sponge_hash;

pub fn sha3_256(mut input: Array<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_256_RATE_BYTES, SHA3_256_DOMAIN, SHA3_256_OUTLEN)
}

pub fn sha3_512(mut input: Array<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_512_RATE_BYTES, SHA3_512_DOMAIN, SHA3_512_OUTLEN)
}

pub fn shake128_xof(mut input: Array<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE128_RATE_BYTES, SHAKE128_DOMAIN, out_len)
}

pub fn shake256_xof(mut input: Array<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE256_RATE_BYTES, SHAKE256_DOMAIN, out_len)
}
fn keccak_sponge_hash(mut input: Array<u8>, rate_bytes : usize, domain : u8, out_len: usize) -> Array<u8> {
    let mut state: Array<u8> = ArrayTrait::new();
    
    // Initialize state with zeros (200 bytes = 1600 bits)
    let mut i: usize = 0;
    while i < 200 {
        state.append(0);
        i += 1;
    }
    
    let mut input_pos: usize = 0;
    let input_len = input.len();
    let mut block_size: usize = 0;
    
    // Absorb phase
    while input_pos < input_len {
        // Calculate block size
        if input_len - input_pos < rate_bytes {
            block_size = input_len - input_pos;
        } else {
            block_size = rate_bytes;
        }
        
        // XOR input block into state
        let mut j: usize = 0;
        while j < block_size {
            let state_val = *state.at(j);
            let input_val = *input.at(input_pos + j);
            state = set_array_at(state, j, state_val ^ input_val);
            // state[j] = state_val ^ input_val;
            j += 1;
        }
        
        input_pos += block_size;
        
        // If block is complete, apply permutation
        if block_size == rate_bytes {
            state = keccak_f_state_permute(state);
        }
    }
    
    // Padding phase
    let current_pos = if input_pos < input_len { input_len - input_pos } else { 0 };
    
    // Add domain suffix
    let state_val = *state.at(current_pos);
    state = set_array_at(state, current_pos, state_val ^ domain);
    // state[current_pos] = state_val ^ domain;
    
    // Check if we need extra block for padding
    if (domain & 0x80) != 0 && current_pos == (rate_bytes - 1) {
        state = keccak_f_state_permute(state);
    }
    
    // Add final padding bit
    let last_pos = rate_bytes - 1;
    let last_val = *state.at(last_pos);
    state = set_array_at(state, last_pos, last_val ^ 0x80);
    
    // Final permutation
    state = keccak_f_state_permute(state);
    
    // Squeeze phase
    let mut output = ArrayTrait::new();
    let mut output_remaining = out_len;
    let mut output_pos: usize = 0;
    
    while output_remaining > 0 {
        // Calculate output block size
        if output_remaining < rate_bytes {
            block_size = output_remaining;
        } else {
            block_size = rate_bytes;
        }
        
        // Copy state to output
        let mut j: usize = 0;
        while j < block_size {
            output.append(*state.at(output_pos + j));
            j += 1;
        }
        
        output_remaining -= block_size;
        output_pos += block_size;
        
        // If more output needed, apply permutation
        if output_remaining > 0 {
            state = keccak_f_state_permute(state);
            output_pos = 0;
        }
    }
    
    output
}

fn keccak_f_state_permute(state : Array<u8>) -> Array<u8>{
    let mut tmp = from_u8Array_to_WordArray(state);
    let mut tmp2 = keccak_f(tmp);
    from_WordArray_to_u8array(tmp2.span())
}

fn set_array_at<T, +Copy<T>, +Drop<T>>(arr: Array<T>, index: usize, new_val: T) -> Array<T> {
    let mut new_arr = ArrayTrait::new();
    let len = arr.len();

    for i in 0..len {
        if i == index {
            new_arr.append(new_val);
        } else {
            new_arr.append(*arr.at(i));
        }
    }
    new_arr
}

fn keccak_f(mut s: Array<Word64> ) -> Array<Word64>{
    let piln = get_keccak_piln().span();
    let rotc = get_keccak_rot().span();
    let rndc = get_keccak_rndc().span();

    let mut round = 0;
    while round < 24{
        // theta
        let mut bc: Array<Word64> = ArrayTrait::new();
        let mut i = 0;
        while i < 5 {
            bc.append( *s[i] ^ *s[i + 5] ^ *s[i + 10] ^ *s[i + 15] ^ *s[i + 20]);
            i+=1;
        }
        i = 0;
        while i < 5 {
            let t = *bc[(i + 4) % 5] ^ (*bc[(i + 1) % 5]).rotl(1);
            let mut j = 0;
            while j < 5 {
                // s[j*5 + i] = s[j*5 + i] ^ t;
                // s = set_array_at(s, j*5+1, *s[j*5 + i] ^ t);
                let lane = *s[j*5 + i];        // get the element first
                let new_val = lane ^ t;        // compute
                s = set_array_at(s, j*5 + 1, new_val); // update
                j+= 1;
            }
            i+= 1;
        }
        //rho & pi
        let mut t = *s[1];
        i = 0;
        while i < 24 {
            let j = *piln[i];
            let j64 : u64 = j.into();
            let tmp = s[1];
            s = set_array_at(s, j64.try_into().unwrap(), t.rotl((*rotc[i]).into()));
            t = *tmp;
            i += 1;
        }
        // Chi
        let mut j = 0;
        while j < 5 {
        // for j in 0..5 {
            let a0 = *s[j*5 + 0];
            let a1 = *s[j*5 + 1];
            let a2 = *s[j*5 + 2];
            let a3 = *s[j*5 + 3];
            let a4 = *s[j*5 + 4];
            s = set_array_at(s, j*5 + 0, a0 ^ ((~a1) & a2));
            s = set_array_at(s, j*5 + 1, a1 ^ ((~a2) & a3));
            s = set_array_at(s, j*5 + 2, a2 ^ ((~a3) & a4));
            s = set_array_at(s, j*5 + 3, a3 ^ ((~a4) & a0));
            s = set_array_at(s, j*5 + 4, a4 ^ ((~a0) & a1));
            j += 1;
        }
        // iota
        let iota : Word64 = *rndc[round];
        // s = set_array_at(s, 0, *s[0] ^ iota);
        let lane = *s[0]^iota;
        let new_val = lane ^ t;
        s = set_array_at(s, 0, new_val);

        round += 1;
    }
    let res = s;
    res
}



// the following is pasted from sha512


// Variable naming is compliant to RFC-6234 (https://datatracker.ietf.org/doc/html/rfc6234)

pub const SHA512_LEN: usize = 64;
pub const U64_BIT_NUM: u64 = 64;

// Powers of two to avoid recomputing
pub const TWO_POW_56: u64 = 0x100000000000000;
pub const TWO_POW_48: u64 = 0x1000000000000;
pub const TWO_POW_40: u64 = 0x10000000000;
pub const TWO_POW_32: u64 = 0x100000000;
pub const TWO_POW_24: u64 = 0x1000000;
pub const TWO_POW_16: u64 = 0x10000;
pub const TWO_POW_8: u64 = 0x100;
pub const TWO_POW_4: u64 = 0x10;
pub const TWO_POW_2: u64 = 0x4;
pub const TWO_POW_1: u64 = 0x2;
pub const TWO_POW_0: u64 = 0x1;

const TWO_POW_7: u64 = 0x80;
const TWO_POW_14: u64 = 0x4000;
const TWO_POW_18: u64 = 0x40000;
const TWO_POW_19: u64 = 0x80000;
const TWO_POW_28: u64 = 0x10000000;
const TWO_POW_34: u64 = 0x400000000;
const TWO_POW_39: u64 = 0x8000000000;
const TWO_POW_41: u64 = 0x20000000000;
const TWO_POW_61: u64 = 0x2000000000000000;

const TWO_POW_64_MINUS_1: u64 = 0x8000000000000000;
const TWO_POW_64_MINUS_6: u64 = 0x40;
const TWO_POW_64_MINUS_8: u64 = 0x100000000000000;
const TWO_POW_64_MINUS_14: u64 = 0x4000000000000;
const TWO_POW_64_MINUS_18: u64 = 0x400000000000;
const TWO_POW_64_MINUS_19: u64 = 0x200000000000;
const TWO_POW_64_MINUS_28: u64 = 0x1000000000;
const TWO_POW_64_MINUS_34: u64 = 0x40000000;
const TWO_POW_64_MINUS_39: u64 = 0x2000000;
const TWO_POW_64_MINUS_41: u64 = 0x800000;
const TWO_POW_64_MINUS_61: u64 = 0x8;

// Max u8 and u64 for bitwise operations
pub const MAX_U8: u64 = 0xff;
pub const MAX_U64: u128 = 0xffffffffffffffff;

#[derive(Drop, Copy, Clone)]
pub struct Word64 {
    pub data: u64,
}

impl WordBitAnd of BitAnd<Word64> {
    fn bitand(lhs: Word64, rhs: Word64) -> Word64 {
        let data = BitAnd::bitand(lhs.data, rhs.data);
        Word64 { data }
    }
}

impl WordBitXor of BitXor<Word64> {
    fn bitxor(lhs: Word64, rhs: Word64) -> Word64 {
        let data = BitXor::bitxor(lhs.data, rhs.data);
        Word64 { data }
    }
}

impl WordBitOr of BitOr<Word64> {
    fn bitor(lhs: Word64, rhs: Word64) -> Word64 {
        let data = BitOr::bitor(lhs.data, rhs.data);
        Word64 { data }
    }
}

impl WordBitNot of BitNot<Word64> {
    fn bitnot(a: Word64) -> Word64 {
        Word64 { data: Bounded::MAX - a.data }
    }
}

impl WordAdd of Add<Word64> {
    fn add(lhs: Word64, rhs: Word64) -> Word64 {
        Word64 { data: lhs.data.wrapping_add(rhs.data) }
    }
}

impl U128IntoWord of Into<u128, Word64> {
    fn into(self: u128) -> Word64 {
        Word64 { data: self.try_into().unwrap() }
    }
}

impl U64IntoWord of Into<u64, Word64> {
    fn into(self: u64) -> Word64 {
        Word64 { data: self }
    }
}

impl U8IntoWord of Into<u8, Word64> {
    fn into(self: u8) -> Word64 {
        Word64 { data: self.into() }
    }
}

impl WordIntoU64 of Into<Word64, u64> {
    fn into(self: Word64) -> u64 {
        self.data
    }
}

impl WordIntoU128 of Into<Word64, u128> {
    fn into(self: Word64) -> u128 {
        self.data.into()
    }
}

/// Trait defining bitwise operations for word types used in cryptographic algorithms.
pub trait WordOperations<T> {
    /// Performs logical right shift operation.
    /// #### Arguments
    /// * `self` - The value to shift
    /// * `n` - Number of positions to shift right
    /// #### Returns
    /// * `T` - The shifted value
    fn shr(self: T, n: u64) -> T;

    /// Performs logical left shift operation.
    /// #### Arguments
    /// * `self` - The value to shift
    /// * `n` - Number of positions to shift left
    /// #### Returns
    /// * `T` - The shifted value
    fn shl(self: T, n: u64) -> T;

    /// Performs rotate right with precomputed power values for efficiency.
    /// #### Arguments
    /// * `self` - The value to rotate
    /// * `two_pow_n` - Precomputed value of 2^n
    /// * `two_pow_64_n` - Precomputed value of 2^(64-n)
    /// #### Returns
    /// * `T` - The rotated value
    fn rotr_precomputed(self: T, two_pow_n: u64, two_pow_64_n: u64) -> T;

    /// Performs rotate left operation.
    /// #### Arguments
    /// * `self` - The value to rotate
    /// * `n` - Number of positions to rotate left
    /// #### Returns
    /// * `T` - The rotated value
    fn rotl(self: T, n: u64) -> T;
}

pub impl Word64WordOperations of WordOperations<Word64> {
    fn shr(self: Word64, n: u64) -> Word64 {
        Word64 { data: OptBitShift::shr(self.data, n.try_into().unwrap()) }
    }
    fn shl(self: Word64, n: u64) -> Word64 {
        Word64 { data: OptBitShift::shl(self.data, n.try_into().unwrap()) }
    }
    // does the work of rotr but with precomputed values 2**n and 2**(64-n)
    fn rotr_precomputed(self: Word64, two_pow_n: u64, two_pow_64_n: u64) -> Word64 {
        Word64 { data: self.data / two_pow_n | self.data.opt_wrapping_mul(two_pow_64_n) }
    }
    fn rotl(self: Word64, n: u64) -> Word64 {
        let data = BitOr::bitor(
            OptBitShift::shl(self.data, n.try_into().unwrap()),
            OptBitShift::shr(self.data, (U64_BIT_NUM - n).try_into().unwrap()),
        );
        Word64 { data }
    }
}


/// Converts byte array to Word64 array for SHA-512 processing
/// #### Arguments
/// * `data` - Array of u8 bytes to convert
/// #### Returns
/// * `Array<Word64>` - Array of Word64 values (8 bytes per word)
fn from_u8Array_to_WordArray(data: Array<u8>) -> Array<Word64> {
    let mut new_arr: Array<Word64> = array![];
    let mut i = 0;

    // Use precomputed powers of 2 for shift left to avoid recomputation
    // Safe to use u64 coz we shift u8 to the left by max 56 bits in u64
    while (i < data.len()) {
        let new_word: u64 = math_shl_precomputed::<u64>((*data[i + 0]).into(), TWO_POW_56)
            + math_shl_precomputed((*data[i + 1]).into(), TWO_POW_48)
            + math_shl_precomputed((*data[i + 2]).into(), TWO_POW_40)
            + math_shl_precomputed((*data[i + 3]).into(), TWO_POW_32)
            + math_shl_precomputed((*data[i + 4]).into(), TWO_POW_24)
            + math_shl_precomputed((*data[i + 5]).into(), TWO_POW_16)
            + math_shl_precomputed((*data[i + 6]).into(), TWO_POW_8)
            + math_shl_precomputed((*data[i + 7]).into(), TWO_POW_0);
        new_arr.append(Word64 { data: new_word });
        i += 8;
    }
    new_arr
}

// Shift left with precomputed powers of 2
fn math_shl_precomputed<T, +Mul<T>, +Rem<T>, +Drop<T>, +Copy<T>, +Into<T, u128>>(
    x: T, two_power_n: T,
) -> T {
    x * two_power_n
}

/// Converts Word64 array back to byte array for final hash output
/// #### Arguments
/// * `data` - Span of Word64 values to convert
/// #### Returns
/// * `Array<u8>` - Array of u8 bytes (8 bytes per word)
fn from_WordArray_to_u8array(data: Span<Word64>) -> Array<u8> {
    let mut arr: Array<u8> = array![];

    let mut i = 0;
    // Use precomputed powers of 2 for shift right to avoid recomputation
    while (i != data.len()) {
        let mut res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_56) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_48) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_40) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_32) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_24) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_16) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_8) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_0) & MAX_U8;
        arr.append(res.try_into().unwrap());
        i += 1;
    }
    arr
}

// Shift right with precomputed powers of 2
/// Performs right shift using precomputed power of 2 value
/// #### Arguments
/// * `x` - Value to shift
/// * `two_power_n` - Precomputed value of 2^n
/// #### Returns
/// * `T` - Result of x / 2^n (equivalent to x >> n)
fn math_shr_precomputed<T, +Div<T>, +Rem<T>, +Drop<T>, +Copy<T>, +Into<T, u128>>(
    x: T, two_power_n: T,
) -> T {
    x / two_power_n
}


// Return the rotation constants
fn get_keccak_rot() -> Array<Word64> {
    let mut rot: Array<Word64> = ArrayTrait::new();
    rot.append(Word64 { data: 0x01 });
    rot.append(Word64 { data: 0x03 });
    rot.append(Word64 { data: 0x06 });
    rot.append(Word64 { data: 0x0A });
    rot.append(Word64 { data: 0x0F });
    rot.append(Word64 { data: 0x15 });
    rot.append(Word64 { data: 0x1C });
    rot.append(Word64 { data: 0x24 });
    rot.append(Word64 { data: 0x2D });
    rot.append(Word64 { data: 0x37 });
    rot.append(Word64 { data: 0x02 });
    rot.append(Word64 { data: 0x0E });
    rot.append(Word64 { data: 0x1B });
    rot.append(Word64 { data: 0x29 });
    rot.append(Word64 { data: 0x38 });
    rot.append(Word64 { data: 0x08 });
    rot.append(Word64 { data: 0x19 });
    rot.append(Word64 { data: 0x2B });
    rot.append(Word64 { data: 0x3E });
    rot.append(Word64 { data: 0x12 });
    rot.append(Word64 { data: 0x27 });
    rot.append(Word64 { data: 0x3D });
    rot.append(Word64 { data: 0x14 });
    rot.append(Word64 { data: 0x2C });
    rot.append(Word64 { data: 0x3C });
    rot
}

// Return the Pi Lane indices
fn get_keccak_piln() -> Array<Word64> {
    let mut piln: Array<Word64> = ArrayTrait::new();
    piln.append(Word64 { data: 10 });
    piln.append(Word64 { data: 7 });
    piln.append(Word64 { data: 11 });
    piln.append(Word64 { data: 17 });
    piln.append(Word64 { data: 18 });
    piln.append(Word64 { data: 3 });
    piln.append(Word64 { data: 5 });
    piln.append(Word64 { data: 16 });
    piln.append(Word64 { data: 8 });
    piln.append(Word64 { data: 21 });
    piln.append(Word64 { data: 24 });
    piln.append(Word64 { data: 4 });
    piln.append(Word64 { data: 15 });
    piln.append(Word64 { data: 23 });
    piln.append(Word64 { data: 19 });
    piln.append(Word64 { data: 13 });
    piln.append(Word64 { data: 12 });
    piln.append(Word64 { data: 2 });
    piln.append(Word64 { data: 20 });
    piln.append(Word64 { data: 14 });
    piln.append(Word64 { data: 22 });
    piln.append(Word64 { data: 9 });
    piln.append(Word64 { data: 6 });
    piln.append(Word64 { data: 1 });
    piln
}

// Returns the Keccak round constants
fn get_keccak_rndc() -> Array<Word64> {
    let mut rndc: Array<Word64> = ArrayTrait::new();
    rndc.append(Word64 { data: 0x0000000000000001 });
    rndc.append(Word64 { data: 0x0000000000008082 });
    rndc.append(Word64 { data: 0x800000000000808a });
    rndc.append(Word64 { data: 0x8000000080008000 });
    rndc.append(Word64 { data: 0x000000000000808b });
    rndc.append(Word64 { data: 0x0000000080000001 });
    rndc.append(Word64 { data: 0x8000000080008081 });
    rndc.append(Word64 { data: 0x8000000000008009 });
    rndc.append(Word64 { data: 0x000000000000008a });
    rndc.append(Word64 { data: 0x0000000000000088 });
    rndc.append(Word64 { data: 0x0000000080008009 });
    rndc.append(Word64 { data: 0x000000008000000a });
    rndc.append(Word64 { data: 0x000000008000808b });
    rndc.append(Word64 { data: 0x800000000000008b });
    rndc.append(Word64 { data: 0x8000000000008089 });
    rndc.append(Word64 { data: 0x8000000000008003 });
    rndc.append(Word64 { data: 0x8000000000008002 });
    rndc.append(Word64 { data: 0x8000000000000080 });
    rndc.append(Word64 { data: 0x000000000000800a });
    rndc.append(Word64 { data: 0x800000008000000a });
    rndc.append(Word64 { data: 0x8000000080008081 });
    rndc.append(Word64 { data: 0x8000000000008080 });
    rndc.append(Word64 { data: 0x0000000080000001 });
    rndc.append(Word64 { data: 0x8000000080008008 });
    rndc
}
