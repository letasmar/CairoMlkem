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

/// d is random seed of 32 bytes, others are mlkem parameters
pub fn kpke_keygen( d : @Array<u8>, k : usize, eta : usize, du : usize, dv: usize) -> keys{
    print!("Running kpke_keygen\n");
    if(d.len() != 32_usize){
        panic!("Seed must be 32 bytes long");
    }
    
    // here perhaps d should be concatenated with k
    // G is SHA3-512
    let (rho, sigma ) = G(d.clone());

    print!("Rho length: {}, Sigma length: {}\n", rho.len(), sigma.len());
    let mut big_n : u8 = 0;
    // generate matrix Ahat
    let mut Ahat : Array<Array<u16>> = ArrayTrait::new();
    let mut i = 0;
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

    // print Ahat size
    println!("Ahat has {} rows", Ahat.len());
    println!("Each row has {} columns", Ahat.at(0).len());

    // generate s vector 
    let mut s : Array<Array<u16>> = ArrayTrait::new();
    i = 0;
    while i < k.try_into().unwrap(){
        s.append(
            sample_poly_cbd(@prfEta(eta, sigma.clone(), big_n),
            eta.try_into().unwrap())
        );
        i += 1;
        big_n += 1;
    }

    //print s size
    println!("s has {} polynomials", s.len());
    println!("Each polynomial has {} coefficients", s.at(0).len());

    // generate e vector
    let mut e : Array<Array<u16>> = ArrayTrait::new();
    i = 0;
    while i < k.try_into().unwrap(){
        e.append(
            sample_poly_cbd(@prfEta(eta, sigma.clone(), big_n),
            eta.try_into().unwrap())
        );
        i += 1;
        big_n += 1;
    }
    // print e size
    println!("e has {} polynomials", e.len());
    println!("Each polynomial has {} coefficients", e.at(0).len());

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

            // idx = 0;
            // while idx < 256{
            //     // tHat[i][idx] = add_mod(*(*tHat[i])[idx], product[i][idx]);
            //     let first : u16 = *(*tHat.at(i.into())).at(idx);
            //     let second : u16 = *product.at(idx);
            //     let sum = add_mod(first, second);
            //     let mut inner_tHat = tHat.at(i.into()).clone();
            //     inner_tHat = set_array_at(inner_tHat, idx, sum);
            //     tHat = set_array_at(tHat, i.into(), inner_tHat);
            //     idx += 1;
            // }
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
    println!("tHat has {} polynomials", tHat.len());
    println!("Each polynomial has {} coefficients", tHat.at(0).len());


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
    print!("Kpke KeyGen End eklength: {} dk length: {}\n", key_pair.ek_len, key_pair.dk_len);
    key_pair
}

// pub fn kpke_encrypt( d : @Array<u8>, k : usize, n1 : usize, du : usize, dv: usize) -> keyCipher{
//     key_init()

    
// }