pub mod mlkem_internal;
pub mod kpke;

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

pub fn keys_init() -> keys{
    keys{
        ek : ArrayTrait::new(),
        dk : ArrayTrait::new(),
        ek_len : 0_u16,
        dk_len : 0_u16
    }
}

pub fn keyCipher_init() -> keyCipher{
    keyCipher{
        key : ArrayTrait::new(),
        c : ArrayTrait::new(),
        k_len : 0_u16,
        c_len : 0_u16
    }
}

pub fn mlkem_key_gen_512() -> keys{
    // internal needs two random 32byte seeds
    mlkem_internal::mlkem_key_gen_512_impl()
}
// pub fn mlkem_key_gen_768() -> keys{
//     mlkem_internal::mlkem_key_gen_768_impl()
// }
// pub fn mlkem_key_gen_1024() -> keys{
//     mlkem_internal::mlkem_key_gen_1024_impl()
// }

/// MLKEM-512 encapsulation
/// # Arguments
/// * `ek` - encapsulation key
/// * `m` - message to be encapsulated - hardcoded for testing
/// # Returns
/// * `keyCipher` - struct containing the shared key and ciphertext
pub fn mlkem_encaps_512( ek : Span<u8> ) -> keyCipher{
    // internal needs one random 32byte for the message
    mlkem_internal::mlkem_encaps_512_impl(ek)
}
// pub fn mlkem_encaps_768( ek : @Array<u8> ) -> keyCipher{
//     // internal needs one random 32byte for the message
//     mlkem_internal::mlkem_encaps_768_impl(ek)
// }
// pub fn mlkem_encaps_1024( ek : @Array<u8> ) -> keyCipher{
//     // internal needs one random 32byte for the message
//     mlkem_internal::mlkem_encaps_1024_impl(ek)
// }


pub fn mlkem_decaps_512( dk : Span<u8>, cipher : Span<u8> ) -> Array<u8>{
    mlkem_internal::mlkem_decaps_512_impl(dk, cipher)
}
// pub fn mlkem_decaps_768( dk : @Array<u8>, cipher : @Array<u8> ) -> Array<u8>{
//     mlkem_internal::mlkem_decaps_768_impl(dk, cipher)
// }
// pub fn mlkem_decaps_1024( dk : @Array<u8>, cipher : @Array<u8> ) -> Array<u8>{
//     mlkem_internal::mlkem_decaps_1024_impl(dk, cipher)
// }