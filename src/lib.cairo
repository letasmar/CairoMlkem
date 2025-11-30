pub mod opt_math;
pub mod wrapping_math;
pub mod hashes;
pub mod utils;
pub mod samples;

pub mod mlkem;
pub mod ntt;
pub mod zq;
pub mod constants;

use mlkem::mlkem_key_gen_512;
use mlkem::mlkem_encaps_512;
use mlkem::mlkem_decaps_512;
use mlkem::mlkem_internal::{get_ek,get_dk, get_cipher};
use mlkem::keyCipher;
use utils::append_n_zeroes;
use constants::{MLKEM_N};

#[executable]
fn main(){
    // try out full mlkem512 flow
    // all random seeds are hardcoded
    let keys = mlkem_key_gen_512();
    // assert!(keys.ek.len() == constants::MLKEM512_ENCAPS_K);
    // assert!(keys.dk.len() == constants::MLKEM512_DECAPS_K);
    // assert!(compare_arrays(keys.ek.span(), get_ek()));
    // assert!(compare_arrays(keys.dk.span(), get_dk()));
    // panic!("Testing MLKEM512 flow:");
    print!("MLKEM512 Key Generation complete.\n");  
    let keyCipher = mlkem_encaps_512(keys.ek.span());
    // assert!(keyCipher.c.len() == constants::MLKEM512_CIPHER);
    // assert!(compare_arrays(keyCipher.c.span(), get_cipher()));
    print!("MLKEM512 Encapsulation complete.\n");
    // print out key bytes
    print_u8_array(keyCipher.key.span());
    let recovered_key = mlkem_decaps_512(keys.dk.span(), keyCipher.c.span());
    print!("MLKEM512 flow complete. Recovered key length: {}\n", recovered_key.len());
    // print!("Shared key bytes:\n");
    // test_decaps();
    // test_ntt();
    // test_multiply_ntt();
    // print_u8_array(recovered_key.span());
}

// fn compare_arrays<T, +Copy<T>, +PartialEq<T>, +Drop<T>>(a: Span<T>, b: Span<T>) -> bool {
fn compare_arrays(a: Span<u8>, b: Span<u8>) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len() {
        if *a.at(i) != *b.at(i) {
            print!("array a bytes:\n");
            print_u8_array(a);
            print!("array b bytes:\n");
            print_u8_array(b);
            return false;
        }
        i += 1;
    }
    return true;
}

fn test_ntt(){
    let mut a = ArrayTrait::new();
    let mut i : u16 = 0;
    while(i < constants::MLKEM_N.try_into().unwrap()){
        a.append(i);
        i += 1;
    }
    let a_span = a.span();
    let a_ntt = ntt::ntt_kyber(a_span);
    let a_invntt = ntt::ntt_kyber_inv(a_ntt);

    assert!(a_span.len() == a_invntt.len());
    for i in 0..a_span.len() {
        // std::cout << "Index " << i << ": original " << input[i] << ", transformed " << transformed[i] << std::endl;
        println!("Index {}: original {}, transformed {}", i, *a_span.at(i), *a_ntt.at(i));
        if(*a_span.at(i) != *a_invntt.at(i)){
            panic!("NTT test failed at index {}: original {}, after invntt {}", i, *a_span.at(i), *a_invntt.at(i));
        }
    }
    assert!(a_span == a_invntt);
    // panic!("NTT test passed");
}

fn test_multiply_ntt(){
    let mut a = ArrayTrait::new();
    let mut b = ArrayTrait::new();
    let mut i : usize = 0;
    let N : usize = MLKEM_N;
    while(i < N){
        a.append(1);
        b.append(2);
        i += 1;
    }
    let a_span = a.span();
    let b_span = b.span();
    let c_ntt = ntt::multiply_ntt_kyber(a_span, b_span);

    assert!(c_ntt.len() == N);
    // for i in 0..a_span.len() {
    //     println!("Index {}: a {}, b {}, multiply {}", i, *a_span.at(i), *b_span.at(i), *c_ntt.at(i));
    // }
    let zeta2 = constants::get_zeta2(MLKEM_N);
    i = 0;
    let expectedh1 : u16 = 4;
    while(i < N/2){
        let zeta2_i = *zeta2.at(i);
        let expectedh0 : u16 = zq::add_mod(2, zq::mul_mod_signed(2, zeta2_i));
        let c_ntt_at_2i = *c_ntt.at(2*i);
        let c_ntt_at_2i1 = *c_ntt.at(2*i + 1);
        assert!(c_ntt_at_2i == expectedh0);
        assert!(c_ntt_at_2i1 == expectedh1);
        // format!("NTT multiplication test failed at index {}: got {}, expected {}", 2*i, c_ntt_at_2i, expectedh0)
        i += 1;
    }

    assert!(c_ntt.len() == a.len());
    // panic!("NTT multiplication test passed");
}

fn test_keygen(){
    let keys = mlkem::mlkem_key_gen_512();
    assert!(keys.ek.len() == constants::MLKEM512_ENCAPS_K);
    assert!(keys.dk.len() == constants::MLKEM512_DECAPS_K);
    let k = constants::MLKEM512_DECAPS_K;
    // println!("DK last {} bytes:", k);
    // print_last_k_bytes(keys.dk.span(), k);
    // println!("EK last {} bytes:", k);
    // print_last_k_bytes(keys.ek.span(), k);
    print!("EK = \n");
    print_u8_array(keys.ek.span());
    print!("DK = \n");
    print_u8_array(keys.dk.span());
    panic!("Keygen test passed");
}

fn test_encaps(){
    println!("Starting encapsulation test");
    let cipher = mlkem::mlkem_encaps_512(get_ek());
    assert!(cipher.c.len() == constants::MLKEM512_CIPHER);
    let k = constants::MLKEM512_CIPHER;
    println!("Ciphertext last {} bytes:", k);
    // print_last_k_bytes(cipher.c.span(), k);
    print_u8_array(cipher.c.span());
    panic!("Encapsulation test passed");
}

fn test_decaps(){
    println!("Starting decapsulation test");
    let recovered_key = mlkem::mlkem_decaps_512(get_dk(), get_cipher());
    assert!(recovered_key.len() == constants::MLKEM512_K);
    let k = 32;
    println!("Recovered key last {} bytes:", k);
    print_last_k_bytes(recovered_key.span(), k);
    panic!("Decapsulation test passed");
}

fn print_last_k_bytes(arr: Span<u8>, k: usize){
    let len = arr.len();
    let start = if len > k { len - k } else { 0 };
    for i in start..len {
        println!("arr.append(0x{:x});", *arr.at(i));
    }
}

fn print_u8_array(arr: Span<u8>) -> () {
    for i in 0..arr.len() {
        println!("0x{:x}", *arr.at(i));
    }
}