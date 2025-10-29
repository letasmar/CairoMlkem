mod keccak;

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

use keccak::keccak_sponge_hash;

// ----------------------------
// Public Hash Functions
// ----------------------------

// Computes SHA3-256 hash of `input`.
// Produces a 32-byte (256-bit) output.
pub fn sha3_256(mut input: Array<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_256_RATE_BYTES, SHA3_256_DOMAIN, SHA3_256_OUTLEN)
}

// Computes SHA3-512 hash of `input`.
// Produces a 64-byte (512-bit) output.
pub fn sha3_512(mut input: Array<u8>) -> Array<u8> {
    keccak_sponge_hash(input, SHA3_512_RATE_BYTES, SHA3_512_DOMAIN, SHA3_512_OUTLEN)
}

// Computes SHAKE128 eXtendable-Output Function.
// The `out_len` parameter specifies how many bytes to generate.
pub fn shake128_xof(mut input: Array<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE128_RATE_BYTES, SHAKE128_DOMAIN, out_len)
}

// Computes SHAKE256 eXtendable-Output Function.
// Like SHAKE128, the `out_len` parameter defines the desired output size.
pub fn shake256_xof(mut input: Array<u8>, out_len: usize) -> Array<u8> {
    keccak_sponge_hash(input, SHAKE256_RATE_BYTES, SHAKE256_DOMAIN, out_len)
}