use crate::mlkem::keys;
use crate::mlkem::keys_init;
use crate::mlkem::keyCipher;
use crate::hashes::{G, prfEta};
use crate::samples::{sample_ntt, sample_poly_cbd};
use crate::ntt::ntt;
use crate::ntt::mul_ntt;
use crate::zq::add_mod;
use crate::utils::array_from_span;
use crate::utils::set_array_at;
use crate::utils::append_n_zeroes;
use crate::utils::byte_encode;
use crate::utils::byte_decode;

/// d is random seed of 32 bytes, others are mlkem parameters
/// keys struct contains ek and dk as u8 arrays
pub fn kpke_keygen( d : @Array<u8>, k : usize, eta : usize, du : usize, dv: usize) -> keys{
    print!("Running kpke_keygen\n");
    if(d.len() != 32_usize){
        panic!("Seed must be 32 bytes long");
    }
    
    // here perhaps d should be concatenated with k
    // G is SHA3-512
    let (rho, sigma ) = G(d.clone());

    // print!("Rho length: {}, Sigma length: {}\n", rho.len(), sigma.len());
    let mut big_n0 : u8 = 0;
    let mut i : u8 = 0;
    // generate matrix Ahat
    let mut Ahat : Array<Array<u16>> = generate_matrix(k, @rho);

    // print Ahat size
    // println!("Ahat has {} rows", Ahat.len());
    // println!("Each row has {} columns", Ahat.at(0).len());

    // generate s vector 
    let (mut s, mut big_n1) = generate_vector( k, @sigma, eta, big_n0);
    // i = 0;
    // while i < k.try_into().unwrap(){
    //     s.append(
    //         sample_poly_cbd(@prfEta(eta, sigma.clone(), big_n),
    //         eta.try_into().unwrap())
    //     );
    //     i += 1;
    //     big_n += 1;
    // }

    //print s size
    // println!("s has {} polynomials", s.len());
    // println!("Each polynomial has {} coefficients", s.at(0).len());

    // generate e vector
    let (mut e, mut big_n2) = generate_vector( k, @sigma, eta, big_n1);
    // print e size
    // println!("e has {} polynomials", e.len());
    // println!("Each polynomial has {} coefficients", e.at(0).len());

    // run ntt on s and e each coordinate
    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let mut e_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in s{
        s_ntt.append(array_from_span(ntt(poly.span())));
    }
    for poly in e{
        e_ntt.append(array_from_span(ntt(poly.span())));
    }

    // declare tHat
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();
    
    // compute t = As + e, first fill t with zeros
    i = 0;
    while i < k.try_into().unwrap(){
        // acc = tHat[i]
        let mut acc: Array<u16> = ArrayTrait::new(); 
        acc = append_n_zeroes(@acc, 256, 0);

        let mut j : usize = 0;
        while j < k {
            let mut idx : usize = (i.into() * k + j).try_into().unwrap();
            let product : Array<u16> = array_from_span(
                mul_ntt( Ahat[idx].span(), s_ntt[j.try_into().unwrap()].span())
            );
            let mut idx2 = 0;
            while idx2 < 256 {
                let sum = add_mod(*acc.at(idx2), *product.at(idx2));
                acc = set_array_at(acc, idx2, sum);
                idx2 += 1;
            }
            j += 1;
        }

        let mut idx : usize = 0;
        while idx < 256{
            // tHat[i][idx] = add_mod(tHat[i][idx], e_ntt[i]);
            let sum = add_mod(*acc.at(idx), *e_ntt.at(i.into()).at(idx));
            acc = set_array_at(acc, idx, sum);
            idx += 1;
        }

        tHat.append(acc);
        i += 1;
    }
    // print tHat size
    // println!("tHat has {} polynomials", tHat.len());
    // println!("Each polynomial has {} coefficients", tHat.at(0).len());


    //use  byte_encode to serialize ek and dk
    let mut key_pair = keys_init();
    // ek is tHat and rho combined
    i = 0;
    while i < k.try_into().unwrap(){
        let encoded_poly = byte_encode(tHat.at(i.into()), 12);
        for byte in encoded_poly{
            key_pair.ek.append(byte);
        }
        i += 1;
    }
    for byte in rho{
        key_pair.ek.append(byte);
    }
    // dk is s_ntt
    i = 0;
    while i < k.try_into().unwrap(){
        let encoded_poly = byte_encode(s_ntt.at(i.into()), 12);
        for byte in encoded_poly{
            key_pair.dk.append(byte);
        }
        i += 1;
    }
    
    key_pair.ek_len = key_pair.ek.len().try_into().unwrap();
    key_pair.dk_len = key_pair.dk.len().try_into().unwrap();
    // print!("Kpke KeyGen End eklength: {} dk length: {}\n", key_pair.ek_len, key_pair.dk_len);
    key_pair
}

/// kpke encryption
/// ek : encapsulation key
/// m : message to be encapsulated
/// r : randomness derived from G
/// k, eta, du, dv : mlkem parameters
/// Returns ciphertext as u8 array
pub fn kpke_encrypt(ek : Array<u8>, m : @Array<u8>, r : @Array<u8>, k : usize, eta : usize, du : usize, dv: usize) -> Array<u8>{
    let mut big_n : u8 = 0;

    // run bytedecode_12 k times to decode tHat and obtain rho from last 32 bytes of ek
    let mut i :u8 = 0;
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();

    while i < k.try_into().unwrap(){
        let start_idx : usize = i.into() * 384;
        let end_idx : usize = start_idx + 384;
        let encoded_poly = ek.span().slice(start_idx, end_idx);
        let tHat_poly = byte_decode(encoded_poly, 12);
        // let enconded_poly = ek.clone().slice(start_idx, end_idx);
        // let tHat_poly = byte_decode(enconded_poly, 12);
        // print!("tHat polynomial {} decoded\n", i);
        i += 1;
    }

    // re-generate Ahat
    //generate y
    //generate e1
    // sample e2

    // compute yhat
    // copmute u through ntt inverse
    // compute mu through decompres
    // compute v
    // compute c1, c2
    // return concat_arrays(c1, c2)

    // placeholder return
    ArrayTrait::new()
}


/// generate vector
pub fn generate_vector( k : usize, sigma : @Array<u8>, eta : usize, mut big_n : u8) -> ( Array<Array<u16>>, u8 ){
    let mut v : Array<Array<u16>> = ArrayTrait::new();
    let mut i : u8= 0;
    while i < k.try_into().unwrap(){
        v.append(
            sample_poly_cbd(@prfEta(eta, sigma.clone(), big_n),
            eta.try_into().unwrap())
        );
        i += 1;
        big_n += 1;
    }
    (v , big_n) 
}

/// generate A matrix
pub fn generate_matrix( k : usize, rho : @Array<u8>) -> Array<Array<u16>>{
    let mut Ahat : Array<Array<u16>> = ArrayTrait::new();
    let mut i : u8 = 0;
    while i < k.try_into().unwrap(){
        let mut j : u8 = 0;
        while j < k.try_into().unwrap(){
            let mut seed = rho.clone();
            seed.append(j);
            seed.append(i);
            Ahat.append(sample_ntt(@seed));
            j += 1;
        }
        i += 1;
    }
    Ahat
}

