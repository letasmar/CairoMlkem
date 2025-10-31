pub mod mlkem_internal;

// parameters for MLKEM
pub const MLKEM_Q: usize = 3329;
pub const MLKEM_Qu16: u16 = 3329;
pub const MLKEM_N: usize = 256;
pub const MLKEM512_ETA1 : usize = 3; // generating s,e in KeyGen, y in Encrypt
pub const MLKEM_ETA : usize = 2; // all other etas
pub const MLKEM512_K: usize = 2;
pub const MLKEM768_K: usize = 3;
pub const MLKEM1024_K: usize = 4;

pub const MLKEM512_DV: usize = 4;
pub const MLKEM768_DV: usize = 4;
pub const MLKEM1024_DV: usize = 5;
pub const MLKEM512_DU: usize = 10;
pub const MLKEM768_DU: usize = 10;
pub const MLKEM1024_DU: usize = 11;

// lengths for keys
pub const MLKEM_SHARED_KEY_LEN : usize = 32;
pub const MLKEM512_ENCAPS_K: usize = 800;
pub const MLKEM768_ENCAPS_K: usize = 1184;
pub const MLKEM1024_ENCAPS_K: usize = 1568;
pub const MLKEM512_DECAPS_K: usize = 1632;
pub const MLKEM768_DECAPS_K: usize = 2400;
pub const MLKEM1024_DECAPS_K: usize = 3168;
pub const MLKEM512_CIPHER: usize = 768;
pub const MLKEM768_CIPHER: usize = 1088;
pub const MLKEM1024_CIPHER: usize = 1568;

/// kem512 verify lengths ek: 800, dk: 1632
/// kem768 verify lengths ek: 1184, dk: 2400
/// kem1024 verify lengths ek: 1568, dk: 3168
#[derive(Drop)]
pub struct keys{
    pub ek : Array<u8>,
    pub dk : Array<u8>,
    pub ek_len : u16,
    pub dk_len : u16
}

/// verify lengths key: 32, ciphertext: 768
/// verify lengths key: 32, ciphertext: 1088
/// verify lengths key: 32, ciphertext: 1568
#[derive(Drop)]
pub struct keyCipher{
    pub key : Array<u8>,
    pub c : Array<u8>,
    pub k_len : u16,
    pub c_len : u16
}

pub fn mlkem_key_gen_512() -> keys{
    // internal needs two random 32byte seeds
    mlkem_internal::mlkem_key_gen_512_impl()
}
pub fn mlkem_key_gen_768() -> keys{
    mlkem_internal::mlkem_key_gen_768_impl()
}
pub fn mlkem_key_gen_1024() -> keys{
    mlkem_internal::mlkem_key_gen_1024_impl()
}

pub fn mlkem_encaps_512( ek : @Array<u8> ) -> keyCipher{
    // internal needs one random 32byte for the message
    mlkem_internal::mlkem_encaps_512_impl(ek)
}
pub fn mlkem_encaps_768( ek : @Array<u8> ) -> keyCipher{
    // internal needs one random 32byte for the message
    mlkem_internal::mlkem_encaps_768_impl(ek)
}
pub fn mlkem_encaps_1024( ek : @Array<u8> ) -> keyCipher{
    // internal needs one random 32byte for the message
    mlkem_internal::mlkem_encaps_1024_impl(ek)
}


pub fn mlkem_decaps_512( dk : @Array<u8>, cipher : @Array<u8> ) -> Array<u8>{
    mlkem_internal::mlkem_decaps_512_impl(dk, cipher)
}
pub fn mlkem_decaps_768( dk : @Array<u8>, cipher : @Array<u8> ) -> Array<u8>{
    mlkem_internal::mlkem_decaps_768_impl(dk, cipher)
}
pub fn mlkem_decaps_1024( dk : @Array<u8>, cipher : @Array<u8> ) -> Array<u8>{
    mlkem_internal::mlkem_decaps_1024_impl(dk, cipher)
}