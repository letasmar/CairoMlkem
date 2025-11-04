pub mod opt_math;
pub mod wrapping_math;
pub mod hashes;
pub mod utils;
pub mod samples;

pub mod mlkem;
pub mod ntt;
pub mod ntt_constants;
pub mod zq;

// use utils::{bytes_to_bits, bits_to_bytes};
// use crate::hashes::{sha3_256, sha3_512, shake128_xof, shake256_xof};
// use mlkem::keys;
// use mlkem::keys_init;
use mlkem::mlkem_key_gen_512;
use mlkem::mlkem_encaps_512;
use mlkem::mlkem_decaps_512;
use mlkem::mlkem_internal::{get_ek,get_dk, get_cipher};
use mlkem::keyCipher;
use utils::append_n_zeroes;

#[executable]
fn main(){
//     let mut i : u32 = 0;
//     while i < 1000 {
//         test_multiply_ntt();
//         print!("Completed iteration {}\n", i);
//         i += 1;
//     }
//     print!("All iterations completed successfully\n");
    // test_keygen();
    test_encaps();
    // test_decaps()
    // let mut a : Array<u8> = ArrayTrait::new();
    // a = append_n_zeroes(a, 10, 0_u8);
    // print!("Array length after appending zeroes: {}\n", a.len());
    // // // test if concat works
    // a.append('a');
    // a.append('b');
    // a.append('c');
    // a.append('1');
    // a.append('2');
    // a.append('3');
    // let mut b = ArrayTrait::new();
    // a.append(255);
    // let b = a.span();
    // let c = b.slice(0,3);
    // for e in c{
    //     print!("{}", e);
    // }
    // print!("\n");
    // let c = b.slice(3,5);
    // for e in c{
    //     print!("{}", e);
    // }
    // print!("slice length: {}\n", c.len());
    // print!("slice start value: {}\n", *c.at(0));


    // let mut b = a.clone();
    // let c = utils::concat_arrays(@a, @b);
    // let mut c = a.clone();
    // let mut d = a.clone();
    // let mut res : Array<Array<u8>> = ArrayTrait::new();
    // let keys = mlkem_key_gen_512();
    // let pke = keys.ek;
    // let ske = keys.dk;

    // res.append(z);
    // res.append(y);
    // res.append(c);
    // let mut res : Array<Array<u8>> = ArrayTrait::new();
    // res.append(sha3_256(a.clone()));
    // res.append(sha3_256(b));
    // res.append(shake128_xof(c, 32));
    // res.append(shake256_xof(d, 32));
    // for e in sha3_256(a.span()){
    //     print!("{:x}",e);
    // }
    // println!("");
    // for element in res.clone(){
    //     println!("{} characters", element.len());
    //     for e in element{
    //         print!("{:x}",e);
    //     }
    //     println!("");
    // }

    // let mut keys = keys_init();
    // keys.ek = get_ek();
    // keys.dk = get_dk();
    // let a = keys.ek.len();
    // let b = keys.dk.len();
    // let cipher = mlkem_encaps_512(@get_ek());

    // let k = mlkem_decaps_512(get_dk(), get_cipher());
    // println!("Code ran! {} bytes in key, {} bytes in secret key", k.len(), 32 );
    // for element in k{
    //         // arr.append(0xe1);
    //     println!("arr.append(0x{:x});", element);
    // }
    // panic!("End of main");
    // println!("DK");
    // for element in keys.dk{
    //     // arr.append(0xe1);
    //     println!("arr.append(0x{:x});", element);
    // }
}

fn test_ntt(){
    let mut a = ArrayTrait::new();
    let mut i : u16 = 0;
    while(i < 256){
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
        // if(*a_span.at(i) != *a_invntt.at(i)){
        //     panic!("NTT test failed at index {}: original {}, after invntt {}", i, *a_span.at(i), *a_invntt.at(i));
        // }
    }
    assert!(a_span == a_invntt);
    // panic!("NTT test passed");
}

fn test_multiply_ntt(){
    let mut a = ArrayTrait::new();
    let mut b = ArrayTrait::new();
    let mut i : usize = 0;
    let N : usize = 256;
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
    let zeta2 = ntt_constants::get_zeta2();
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
    assert!(keys.ek.len() == mlkem::MLKEM512_ENCAPS_K);
    assert!(keys.dk.len() == mlkem::MLKEM512_DECAPS_K);
    let k = mlkem::MLKEM512_DECAPS_K;
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
    assert!(cipher.c.len() == mlkem::MLKEM512_CIPHER);
    let k = mlkem::MLKEM512_CIPHER;
    println!("Ciphertext last {} bytes:", k);
    // print_last_k_bytes(cipher.c.span(), k);
    print_u8_array(cipher.c.span());
    panic!("Encapsulation test passed");
}

fn test_decaps(){
    println!("Starting decapsulation test");
    let recovered_key = mlkem::mlkem_decaps_512(get_dk(), get_cipher());
    assert!(recovered_key.len() == mlkem::MLKEM512_K);
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
        println!("arr.append(0x{:x});", *arr.at(i));
    }
}