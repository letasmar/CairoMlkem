use crate::mlkem::keys;
use crate::mlkem::keys_init;
use crate::hashes::{G, prfEta};
use crate::samples::{sample_ntt, sample_poly_cbd};
use crate::ntt::ntt_kyber;
use crate::ntt::ntt_kyber_inv;
use crate::ntt::multiply_ntt_kyber;
use crate::zq::add_mod;
use crate::zq::sub_mod;
use crate::utils::array_from_span;
use crate::utils::append_n_zeroes;
use crate::utils::byte_encode;
use crate::utils::byte_decode;
use crate::utils::decompress;
use crate::utils::compress;
use crate::utils::concat_arrays;
use crate::constants::{MLKEM_ETA, MLKEM_N};

/// d is random seed of 32 bytes, others are mlkem parameters
/// keys struct contains ek and dk as u8 arrays
pub fn kpke_keygen( d : Span<u8>, k : usize, eta : usize, du : usize, dv: usize) -> keys{
    // print!("Running kpke_keygen\n");
    if(d.len() != 32_usize){
        panic!("Seed must be 32 bytes long");
    }
    
    // G is SHA3-512
    let (rho, sigma ) = G(d.clone());
    
    let mut big_n0 : u8 = 0;
    // generate matrix Ahat
    let mut Ahat : Array<Array<u16>> = generate_matrix(k, rho.clone());

    // generate s vector 
    let (mut s, mut big_n1) = generate_vector( k, sigma.span(), eta, big_n0);
    
    // generate e vector
    let (mut e, mut _big_n2) = generate_vector( k, sigma.span(), eta, big_n1);
    
    // run ntt on s and e each coordinate
    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let mut e_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in s.span(){
        s_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }
    for poly in e.span(){
        e_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }

    // declare tHat
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();
    
    // compute t = As + e, first fill t with zeros
    let mut i : usize = 0;
    while i < k{
        // acc = tHat[i]
        let mut acc: Array<u16> = ArrayTrait::new(); 
        acc = append_n_zeroes(acc, 256, 0);

        let mut j : usize = 0;
        while j < k {
            let mut idx : usize = (i * k + j);
            let product : Array<u16> = array_from_span(
                multiply_ntt_kyber( Ahat[idx].span(), s_ntt[j].span())
            );
            let mut idx2 = 0;
            let mut tmp : Array<u16> = ArrayTrait::new();
            while idx2 < MLKEM_N {
                let sum = add_mod(*acc.at(idx2), *product.at(idx2));
                tmp.append(sum);
                // acc = set_array_at(acc, idx2, sum);
                idx2 += 1;
            }
            acc = tmp;
            j += 1;
        }

        let mut idx : usize = 0;
        let mut tmp2 : Array<u16> = ArrayTrait::new();
        while idx < MLKEM_N{
            // tHat[i][idx] = add_mod(tHat[i][idx], e_ntt[i]);
            let sum = add_mod(*acc.at(idx), *e_ntt.at(i).at(idx));
            // acc = set_array_at(acc, idx, sum);
            tmp2.append(sum);
            idx += 1;
        }
        acc = tmp2;

        tHat.append(acc);
        i += 1;
    }
    let mut key_pair = keys_init();
    i = 0;
    while i < k.try_into().unwrap(){
        let encoded_poly = byte_encode(tHat[i.into()].span(), 12);
        for byte in encoded_poly{
            key_pair.ek.append(byte);
        }
        i += 1;
    }
    for byte in rho{
        key_pair.ek.append(byte);
    }
    i = 0;
    while i < k.try_into().unwrap(){
        let encoded_poly = byte_encode(s_ntt[i.into()].span(), 12);
        for byte in encoded_poly{
            key_pair.dk.append(byte);
        }
        i += 1;
    }
    
    key_pair.ek_len = key_pair.ek.len().try_into().unwrap();
    key_pair.dk_len = key_pair.dk.len().try_into().unwrap();
    key_pair
}

/// kpke encryption
/// ek : encapsulation key
/// m : message to be encapsulated
/// r : randomness derived from G
/// k, eta, du, dv : mlkem parameters
/// Returns ciphertext as u8 array
pub fn kpke_encrypt(ek_span : Span<u8>, m : Span<u8>, r : Span<u8>, k : usize, eta : usize, du : usize, dv: usize) -> Array<u8>{
    let mut big_n : u8 = 0;
    let mut eta2 : usize = MLKEM_ETA; // eta2 is same for all variants
    let mut i :usize = 0;
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();
    let bytes_per_poly : usize = MLKEM_N * 12 / 8;
    while i < k{
        let start_idx : usize = i * bytes_per_poly;
        let encoded_poly = ek_span.slice(start_idx, bytes_per_poly);
        tHat.append(byte_decode(encoded_poly, 12));
        i += 1;
    }

    let rho_start_idx : usize = k * bytes_per_poly;
    let rho = ek_span.slice(rho_start_idx, 32);

    // re-generate Ahat
    let Ahat : Array<Array<u16>> = generate_matrix(k, array_from_span(rho));
    let (mut y, mut big_n1) = generate_vector( k, r, eta, big_n);
    big_n = big_n1;

    //generate e1
    let (mut e1, mut big_n2) = generate_vector( k, r, eta2, big_n);
    big_n = big_n2;

    let e2 : Array<u16> = sample_poly_cbd(prfEta(eta2, r, big_n).span(), eta2);
    big_n += 1;

    // compute yhat - ntt of y
    i = 0;
    let mut y_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in y{
        y_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }

    let mut uHat : Array<Array<u16>> = ArrayTrait::new();
    i = 0;
    while i < k.try_into().unwrap(){
        // acc = uHat[i]
        let mut acc: Array<u16> = ArrayTrait::new();
        acc = append_n_zeroes(acc, MLKEM_N, 0);
        let mut j : usize = 0;
        while j < k {
            let mut idx_1 : usize = (j * k + i.into());
            let Ahat_idx = Ahat.at(idx_1);
            let y_ntt_j = y_ntt.at(j);
            let product = multiply_ntt_kyber(Ahat_idx.span(), y_ntt_j.span());

            let mut idx2 = 0;
            let mut tmp : Array<u16> = ArrayTrait::new();
            while idx2 < MLKEM_N {
                let sum = add_mod(*acc.at(idx2), *product.at(idx2));
                // acc = set_array_at(acc, idx2, sum); - expensive
                tmp.append(sum);
                idx2 += 1;
            }
            acc = tmp;
            j += 1;
        }
        // ntt inverse on acc
        let acc_inv = ntt_kyber_inv(acc.span());
        // add e1
        let mut idx3 = 0;
        let mut acc2: Array<u16> = ArrayTrait::new();
        while idx3 < MLKEM_N {
            let e1_i = e1.at(i);
            let sum = add_mod(*acc_inv.at(idx3), *e1_i.at(idx3));
            acc2.append(sum);
            idx3 += 1;
        }
        uHat.append(acc2);
        i += 1
    }
    // compute mu through decompress
    let mu : Array<u16> = decompress(byte_decode(m, 1).span(), 1);
    // compute v
    let mut v : Array<u16> = ArrayTrait::new();
    let mut acc: Array<u16> = ArrayTrait::new();
    acc = append_n_zeroes(acc, MLKEM_N, 0);
    i = 0;

    while i < k.try_into().unwrap(){
        let tHat_i = tHat.at(i.into());
        let y_ntt_i = y_ntt.at(i.into());
        let product = multiply_ntt_kyber(tHat_i.span(), y_ntt_i.span());
        let mut idx2 = 0;
        let mut tmp : Array<u16> = ArrayTrait::new();
        while idx2 < MLKEM_N {
            let sum = add_mod(*acc.at(idx2), *product.at(idx2));
            tmp.append(sum);
            idx2 += 1;
        }
        acc = tmp;
        i += 1;
    }
    let acc_inv = ntt_kyber_inv(acc.span());
    let mut idx3 = 0;
    while idx3 < MLKEM_N{
        let sum1 = add_mod(*acc_inv.at(idx3), *e2.at(idx3));
        let sum2 = add_mod(sum1, *mu.at(idx3));
        v.append(sum2);
        idx3 += 1;
    }

    // compute c1, c2
    let mut c1 : Array<u8> = ArrayTrait::new();
    let c2 : Array<u8> = byte_encode(compress(v.span(), dv).span(), dv);

    // uHat is a vector of k polynomials in ring n
    i = 0;
    while i < k.try_into().unwrap(){
        let uHat_i = uHat.at(i.into());
        let compressed_poly = compress(uHat_i.span(), du);
        let encoded_poly = byte_encode(compressed_poly.span(), du);
        for byte in encoded_poly{
            c1.append(byte);
        }
        i += 1;
    }

    array_from_span(concat_arrays(c1.span(), c2.span()))
}

pub fn kpke_decrypt(dk: Span<u8>, cipher: Span<u8>, k: usize, eta: usize, du: usize, dv: usize) -> Array<u8> {
    // get c_1 and c_2 from cipher
    let c1_bytes : usize = ((du * MLKEM_N  + 7) / 8) * k;
    // print!("c1_bytes: {}\n", c1_bytes);

    let c1 = cipher.slice(0, c1_bytes);
    let c2 = cipher.slice(c1_bytes, cipher.len() - c1_bytes);

    // reconstruct uHat from c1
    let mut uHat : Array<Array<u16>> = ArrayTrait::new();
    let mut i : usize = 0;
    while i < k {
        let offset : usize = i * c1_bytes / k;
        let encoded_poly = c1.slice(offset, c1_bytes / k);
        let decoded_poly = byte_decode(encoded_poly, du);
        let decompressed_poly = decompress(decoded_poly.span(), du);
        uHat.append(decompressed_poly);
        i += 1;
    }

    // reconstruct v from c2
    let decoded_v = byte_decode(c2, dv);
    let v = decompress(decoded_v.span(), dv);
    

    // reconstruct s from dk
    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let bytesPerPoly : usize = ((12 * MLKEM_N + 7) / 8);
    i = 0;
    while i < k {
        let offset : usize = i * bytesPerPoly;
        let encoded_poly = dk.slice(offset, bytesPerPoly);
        let decoded_poly = byte_decode(encoded_poly, 12);
        s_ntt.append(decoded_poly);
        i += 1;
    }

    // compute w
    let mut w : Array<u16> = ArrayTrait::new();

    w = append_n_zeroes(w, MLKEM_N, 0);
    i = 0;
    while i < k.try_into().unwrap(){
        let uHat_i = uHat.at(i.into());
        let u_ntt_i = ntt_kyber(uHat_i.span());
        let s_ntt_i = s_ntt.at(i.into());
        let product = multiply_ntt_kyber(u_ntt_i, s_ntt_i.span());
        let mut idx2 = 0;
        let mut tmp : Array<u16> = ArrayTrait::new();
        while idx2 < MLKEM_N {
            let sum = add_mod(*w.at(idx2), *product.at(idx2));
            // w = set_array_at(w, idx2, sum);
            tmp.append(sum);
            idx2 += 1;
        }
        w = tmp;
        i += 1;
    }
    // ntt inverse on w
    let w_inv = ntt_kyber_inv(w.span());
    let mut final_w = ArrayTrait::new();
    i = 0;
    while i < MLKEM_N{
        final_w.append(sub_mod(*v.at(i), *w_inv.at(i)));
        i += 1;
    }
    w = final_w;
    let compressed_w = compress(w.span(), 1);
    byte_encode(compressed_w.span(), 1) 
}

/// generate vector
pub fn generate_vector( k : usize, sigma : Span<u8>, eta : usize, mut big_n : u8) -> ( Array<Array<u16>>, u8 ){
    let mut v : Array<Array<u16>> = ArrayTrait::new();
    let mut i : u8= 0;
    // print!("Generating vector with {} polynomials\n", k);
    while i < k.try_into().unwrap(){
        let val = sample_poly_cbd(prfEta(eta, sigma, big_n).span(), eta.try_into().unwrap());
        v.append(val);
        i += 1;
        big_n += 1;
    }
    (v , big_n) 
}

/// generate A matrix
pub fn generate_matrix( k : usize, mut rho : Array<u8>) -> Array<Array<u16>>{
    let mut Ahat : Array<Array<u16>> = ArrayTrait::new();
    let mut i : u8 = 0;
    while i < k.try_into().unwrap(){
        let mut j : u8 = 0;
        while j < k.try_into().unwrap(){
            let mut seed = rho.clone();
            seed.append(j);
            seed.append(i);
            let val = sample_ntt(seed.span());
            Ahat.append(val);
            j += 1;
        }
        i += 1;
    }
    Ahat
}

