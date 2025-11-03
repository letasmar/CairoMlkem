pub mod keccak;

pub const SHA3_256_RATE_BYTES: usize = 136;
pub const SHA3_256_DOMAIN: u8 = 0x06;
pub const SHA3_256_OUTLEN: usize = 32;
pub const SHA3_512_RATE_BYTES: usize = 72;
pub const SHA3_512_DOMAIN: u8 = 0x06;
pub const SHA3_512_OUTLEN: usize = 64;

pub const SHAKE128_RATE_BYTES: usize = 168;
pub const SHAKE128_DOMAIN: u8 = 0x1F;
pub const SHAKE256_RATE_BYTES: usize = 136;
pub const SHAKE256_DOMAIN: u8 = 0x1F;

use keccak::keccak_sponge_hash;
use crate::utils::concat_arrays;

// ----------------------------
// Public Hash Functions
// ----------------------------

/// Computes SHA3-256 hash of `input`.
/// Produces a 32-byte (256-bit) output.
pub fn sha3_256(input: Span<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_256_RATE_BYTES, SHA3_256_DOMAIN, SHA3_256_OUTLEN)
}

/// Computes SHA3-512 hash of `input`.
/// Produces a 64-byte (512-bit) output.
pub fn sha3_512(input: Span<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_512_RATE_BYTES, SHA3_512_DOMAIN, SHA3_512_OUTLEN)
}

/// Computes SHAKE128 eXtendable-Output Function.
/// The `out_len` parameter specifies how many bytes to generate.
pub fn shake128_xof(input: Span<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE128_RATE_BYTES, SHAKE128_DOMAIN, out_len)
}

/// Computes SHAKE256 eXtendable-Output Function.
/// Like SHAKE128, the `out_len` parameter defines the desired output size.
pub fn shake256_xof(input: Span<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE256_RATE_BYTES, SHAKE256_DOMAIN, out_len)
}

// ----------------------------
// Additional Naming for the MLKEM PRF Functions
// ----------------------------

/// takes variable length input, produces 32bytes of sha3-256
pub fn H( input : Span<u8> ) -> Array<u8>{
    sha3_256(input)
}

/// input should be 32 bytes, produces output according to eta*64
pub fn prfEta( eta: usize, input : Span<u8>, byte: u8) -> Array<u8>{
    if(input.len() != 32_usize){
        panic!("Input must be 32 bytes long");
    }
    let mut array_from_byte = ArrayTrait::new();
    array_from_byte.append(byte);
    let input_ext = concat_arrays(input, array_from_byte.span());
    shake256_xof(input_ext, eta * 64)
}

/// takes variable length input, produces 32bytes of shake256 output
pub fn J(input : Span<u8>) -> Array<u8>{
    shake256_xof(input, 32)
}

/// takes variable length input, produces 2 * 32 bytes of sha3-512
pub fn G(input: Span<u8>) -> (Array<u8>, Array<u8>){
    let hash_output = sha3_512(input);
    let mut out1 = ArrayTrait::new();
    let mut out2 = ArrayTrait::new();
    let mut i = 0;
    while i < 64{
        if(i < 32){
            out1.append(*hash_output[i]);
        } else {
            out2.append(*hash_output[i]);
        }
        i += 1;
    }
    (out1, out2)
}


#[derive(Drop, Clone)]
pub struct SpongeContext {
    state: Array<u8>,
    rate_bytes: usize,
    domain: u8,
}