// the most of the following is pasted from sha512 Alexandria package - namely constants for sha512 and Word64 struct with interfaces
// accessed on the 29th October, 2025 https://github.com/keep-starknet-strange/alexandria/blob/ab6d8ca6be71a62c26799c2ec7f91814cde48b54/packages/math/src/sha512.cairo

// Variable naming is compliant to RFC-6234 (https://datatracker.ietf.org/doc/html/rfc6234)

use crate::opt_math::{OptBitShift, OptWrapping};
use core::num::traits::{Bounded, WrappingAdd};
use core::traits::{BitAnd, BitOr, BitXor, BitNot};

pub fn set_array_at<T, +Copy<T>, +Drop<T>>(arr: Array<T>, index: usize, new_val: T) -> Array<T> {
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
pub const TWO_POW_7: u64 = 0x80;
pub const TWO_POW_6: u64 = 0x40;
pub const TWO_POW_5: u64 = 0x20;
pub const TWO_POW_4: u64 = 0x10;
pub const TWO_POW_3: u64 = 0x80;
pub const TWO_POW_2: u64 = 0x4;
pub const TWO_POW_1: u64 = 0x2;
pub const TWO_POW_0: u64 = 0x1;

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
pub fn from_u8Array_to_WordArray(data: Array<u8>) -> Array<Word64> {
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

/// Little Endian Converts byte array to Word64 array for SHA-512 processing
/// #### Arguments
/// * `data` - Array of u8 bytes to convert
/// #### Returns
/// * `Array<Word64>` - Array of Word64 values (8 bytes per word)
pub fn from_u8Array_to_WordArray_Le(data: Array<u8>) -> Array<Word64> {
    let mut new_arr: Array<Word64> = array![];
    let mut i = 0;

    // Use precomputed powers of 2 for shift left to avoid recomputation
    // Safe to use u64 coz we shift u8 to the left by max 56 bits in u64
    while (i < data.len()) {
        let new_word: u64 = 
            math_shl_precomputed((*data[i + 0]).into(), TWO_POW_0) +
            math_shl_precomputed((*data[i + 1]).into(), TWO_POW_8) +
            math_shl_precomputed((*data[i + 2]).into(), TWO_POW_16) +
            math_shl_precomputed((*data[i + 3]).into(), TWO_POW_24) +
            math_shl_precomputed((*data[i + 4]).into(), TWO_POW_32) +
            math_shl_precomputed((*data[i + 5]).into(), TWO_POW_40) +
            math_shl_precomputed((*data[i + 6]).into(), TWO_POW_48) +
            math_shl_precomputed((*data[i + 7]).into(), TWO_POW_56);
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

/// Little Endian Converts Word64 array back to byte array for final hash output
/// #### Arguments
/// * `data` - Span of Word64 values to convert
/// #### Returns
/// * `Array<u8>` - Array of u8 bytes (8 bytes per word)
pub fn from_WordArray_to_u8array_Le(data: Span<Word64>) -> Array<u8> {
    let mut arr: Array<u8> = array![];
    
    let mut i = 0;
    // Use precomputed powers of 2 for shift right to avoid recomputation
    while (i != data.len()) {
        let mut res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_0) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_8) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_16) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_24) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_32) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_40) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_48) & MAX_U8;
        arr.append(res.try_into().unwrap());
        res = math_shr_precomputed((*data.at(i).data).into(), TWO_POW_56) & MAX_U8;
        arr.append(res.try_into().unwrap());
        i += 1;
    }
    arr
}

/// Converts Word64 array back to byte array for final hash output
/// #### Arguments
/// * `data` - Span of Word64 values to convert
/// #### Returns
/// * `Array<u8>` - Array of u8 bytes (8 bytes per word)
pub fn from_WordArray_to_u8array(data: Span<Word64>) -> Array<u8> {
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


// end of Alexandria package

// Converts an array of MSB bits to a Array of bytes(u8)
pub fn bits_to_bytes(bits: Array<u8>) -> Array<u8> {
    if(bits.len() % 8 != 0){
        panic!("alignment issues");
    }
    let mut bytes : Array<u8> = ArrayTrait::new();
    let mut i = 0;
    while(i < 8*bits.len()){
        let byte : u8 = 
            *bits[i + 0] * TWO_POW_0.try_into().unwrap() +
            *bits[i + 1] * TWO_POW_1.try_into().unwrap() +
            *bits[i + 2] * TWO_POW_2.try_into().unwrap() +
            *bits[i + 3] * TWO_POW_3.try_into().unwrap() +
            *bits[i + 4] * TWO_POW_4.try_into().unwrap() +
            *bits[i + 5] * TWO_POW_5.try_into().unwrap() +
            *bits[i + 6] * TWO_POW_6.try_into().unwrap()// +
            // *bits[i + 7] * TWO_POW_7.try_into().unwrap()
            ;
        bytes.append(byte);
        i += 8;
    }
    bytes

}


/// Converts an array of bytes to an array of bits (0/1).
/// Most-significant-bit first per byte.
pub fn bytes_to_bits(bytes: Array<u8>) -> Array<u8> {
    let mut c = bytes.clone();
    let mut bits : Array<u8> = ArrayTrait::new();
    let mut i = 0;
    while i < bytes.len() { 
        let mut j = 0_u8;
        let mut c_i = *c[i];
        while j < 8 {
            bits.append(c_i % 2);
            c_i = c_i / 2;
            j += 1;
        }
        i += 1;
    }
    bits
}
// Output: bit array 𝑏 ∈ {0, 1}8⋅ℓ.
// 1: 𝐶 ← 𝐵 ▷ copy 𝐵 into array 𝐶 ∈ 𝔹ℓ
// 2: for (𝑖 ← 0; 𝑖 < ℓ; 𝑖++)
// 3: for (𝑗 ← 0; 𝑗 < 8; 𝑗++)
// 4: 𝑏[8𝑖 + 𝑗] ← 𝐶[𝑖] mod 2
// 5: 𝐶[𝑖] ← ⌊𝐶[𝑖]/2⌋
// 6: end for
// 7: end for
// 8: return b


pub fn pow(base: u8, exponent: u32) -> u8 {
    let mut result: u8 = 1;
    let mut i: u32 = 0;

    while i < exponent {
        result = result * base;
        i += 1;
    }

    result
}

// pub fn bytes_to_bits(bytes: Array<u8>) -> Array<u8> {
//     let mut bits = ArrayTrait::new();
//     let mut i = 0;
//     while i < bytes.len() {
//         let mut b = *bytes.at(i);
//         let mut bit = (b / TWO_POW_7.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_6.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_5.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_4.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_3.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_2.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = (b / TWO_POW_1.try_into().unwrap()) % 2;
//         bits.append(bit);
//         bit = b % 2;
//         bits.append(bit);
//         i += 1;
//     }
//     bits
// }