use crate::mlkem::keys;
use crate::mlkem::keys_init;
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
use crate::utils::decompress;
use crate::utils::compress;
use crate::utils::concat_arrays;

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
pub fn kpke_encrypt(ek : @Array<u8>, m : @Array<u8>, r : @Array<u8>, k : usize, eta : usize, du : usize, dv: usize) -> Array<u8>{
    let mut big_n : u8 = 0;
    print!("Running kpke_encrypt\n");
    // run bytedecode_12 k times to decode tHat and obtain rho from last 32 bytes of ek
    let mut i :u8 = 0;
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();
    let ek_span = ek.span();

    // print out accessed indexes for debugging
    println!("ek length: {}", ek_span.len());
    println!("last byte index: {}", *ek_span.at(799));
    println!("k value: {}", k);
    while i < k.try_into().unwrap(){
        print!("1This should display {} times\n", k);
        let start_idx : usize = i.into() * 384;
        let end_idx : usize = start_idx + 384;
        print!("Accessing ek from index {} to {}\n", start_idx, end_idx);
        let encoded_poly = ek_span.slice(start_idx, 384);
        print!("2This should display {} times\n", k);
        // change everything to use spans
        tHat.append(byte_decode(@array_from_span(encoded_poly), 12));
        // let enconded_poly = ek.clone().slice(start_idx, end_idx);
        // let tHat_poly = byte_decode(enconded_poly, 12);
        // print!("tHat polynomial {} decoded\n", i);
        i += 1;
    }

    // obtain rho
    let rho_start_idx : usize = k * 384;
    let rho = ek_span.slice(rho_start_idx, 32);
    print!("Rho obtained\n");



    // re-generate Ahat
    let Ahat : Array<Array<u16>> = generate_matrix(k, @array_from_span(rho));
    println!("Ahat regenerated with dimensions: {} x {}\n", Ahat.len(), Ahat.at(0).len());
    //generate y
    let (mut y, mut big_n1) = generate_vector( k, r, eta, big_n);
    big_n = big_n1;
    
    //generate e1
    let (mut e1, mut big_n2) = generate_vector( k, r, eta, big_n);
    big_n = big_n2;

    // sample e2, as a single vector
    let e2 : Array<u16> = sample_poly_cbd(@prfEta(eta, r.clone(), big_n), eta);
    


    // compute yhat - ntt of y
    i = 0;
    let mut y_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in y{
        y_ntt.append(array_from_span(ntt(poly.span())));
    }

    print!("y_ntt computed\n");
    // copmute u through ntt inverse
    let mut uHat : Array<Array<u16>> = ArrayTrait::new();
    i = 0;
    while i < k.try_into().unwrap(){
        // acc = uHat[i]
        let mut acc: Array<u16> = ArrayTrait::new();
        acc = append_n_zeroes(@acc, 256, 0);
        let mut j : usize = 0;
        while j < k {
            // println!("d1ebug: i = {}, j = {}", i, j);
            let mut idx_1 : usize = (j * k + i.into()).try_into().unwrap();
            let Ahat_idx = Ahat.at(idx_1);
            let y_ntt_j = y_ntt.at(j.try_into().unwrap());
            // println!("d1ebug: i = {}, j = {}", i, j);
            let product = array_from_span(mul_ntt(Ahat_idx.span(), y_ntt_j.span()));
            // println!("product length: {}", product.len());
            // println!("acc length: {}", acc.len());

            // let product : Array<u16> = array_from_span(
            //     mul_ntt( Ahat[idx_1].span(), y_ntt[j.try_into().unwrap()].span())
            // );
            // acc[i] = acc[i] + product[i] mod q
            let mut idx2 = 0;
            while idx2 < 256 {
                let sum = add_mod(*acc.at(idx2), *product.at(idx2));
                acc = set_array_at(acc, idx2, sum);
                idx2 += 1;
            }
            j += 1;
        }
        // ntt inverse on acc
        let acc_inv = array_from_span(ntt(acc.span()));
        // add e1
        let mut idx3 = 0;
        let mut acc2: Array<u16> = ArrayTrait::new();
        while idx3 < 256{
            let e1_i = e1.at(i.into());
            let sum = add_mod(*acc_inv.at(idx3), *e1_i.at(idx3));
            // let sum = add_mod(*acc_inv.at(idx3), *e1.at(i.into()).at(idx3));

            acc2.append(sum);
            idx3 += 1;
        }
        uHat.append(acc2);
        i += 1
    }
    // compute mu through decompress
    println!("Computing mu through decompress\n");
    let mu : Array<u16> = decompress(@byte_decode(m, 1) , 1);
    // compute v
    println!("Computing v\n");
    let mut v : Array<u16> = ArrayTrait::new();
    // first compute tHat * y_ntt
    let mut acc: Array<u16> = ArrayTrait::new();
    acc = append_n_zeroes(@acc, 256, 0);
    i = 0;

    println!("Computing tHat * y_ntt\n");
    while i < k.try_into().unwrap(){
        let tHat_i = tHat.at(i.into());
        let y_ntt_i = y_ntt.at(i.into());
        let product = array_from_span(mul_ntt(tHat_i.span(), y_ntt_i.span()));
        // let product : Array<u16> = array_from_span(
        //     mul_ntt( tHat[i.into()].span(), y_ntt[i.into()].span())
        // );
        print!("Multiplying tHat[{}] and y_ntt[{}]\n", i, i);
        let mut idx2 = 0;
        while idx2 < 256 {
            let sum = add_mod(*acc.at(idx2), *product.at(idx2));
            acc = set_array_at(acc, idx2, sum);
            idx2 += 1;
        }
        i += 1;
    }
    println!("tHat * y_ntt computed\n");
    // ntt inverse on acc
    let acc_inv = array_from_span(ntt(acc.span()));
    // add e2 and mu
    let mut idx3 = 0;
    print!("Adding e2 and mu to acc_inv to compute v\n");
    while idx3 < 256{
        let sum1 = add_mod(*acc_inv.at(idx3), *e2.at(idx3));
        let sum2 = add_mod(sum1, *mu.at(idx3));
        v.append(sum2);
        idx3 += 1;
    }
    print!("v computed\n");
    // compute c1, c2
    let mut c1 : Array<u8> = ArrayTrait::new();
    let c2 : Array<u8> = byte_encode(@compress(@v, dv), dv);

    print!("Computing c1\n");
    i = 0;
    while i < k.try_into().unwrap(){
        let uHat_i = uHat.at(i.into());
        let compressed_poly = compress(uHat_i, du);
        let encoded_poly = byte_encode(@compressed_poly, du);
        for byte in encoded_poly{
            c1.append(byte);
        }
        i += 1;
    }


    // return concat_arrays(c1, c2)
    print!("kpke_encrypt End\n");
    concat_arrays(@c1, @c2)
}

pub fn kpke_decrypt(dk: Span<u8>, cipher: Span<u8>, k: usize, eta: usize, du: usize, dv: usize) -> Array<u8> {
    // print!("Running kpke_decrypt\n");
    // get c_1 and c_2 from cipher
    let c1 = cipher.slice(0, 32 * k * du);
    let c2 = cipher.slice(32 * k * du, cipher.len() - (32 * k * du));

    let c1_bytes : usize = ((du * 256  + 7) / 8) * k;
    let c2_bytes : usize = ((dv * 256  + 7) / 8);

    // reconstruct uHat from c1
    let mut uHat : Array<Array<u16>> = ArrayTrait::new();
    let mut i : usize = 0;
    while i < k {
        let offset : usize = i * c1_bytes / k;
        let encoded_poly = c1.slice(offset, c1_bytes / k);
        let decoded_poly = byte_decode(@array_from_span(encoded_poly), du);
        let decompressed_poly = decompress(@decoded_poly, du);
        uHat.append(decompressed_poly);
        i += 1;
    }
    // reconstruct v from c2
    let decoded_v = byte_decode(@array_from_span(c2), dv);
    let v = decompress(@decoded_v, dv);

    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let bytesPerPoly : usize = ((12 * 256 + 7) / 8);
    i = 0;
    while i < k {
        let offset : usize = i * bytesPerPoly;
        let encoded_poly = dk.slice(offset, bytesPerPoly);
        let decoded_poly = byte_decode(@array_from_span(encoded_poly), 12);
        s_ntt.append(decoded_poly);
        i += 1;
    }

    // compute w
    let mut w : Array<u16> = ArrayTrait::new();

    w = append_n_zeroes(@w, 256, 0);
    i = 0;
    while i < k.try_into().unwrap(){
        let uHat_i = uHat.at(i.into());
        let s_ntt_i = s_ntt.at(i.into());
        let product = array_from_span(mul_ntt(uHat_i.span(), s_ntt_i.span()));
        // let product : Array<u16> = array_from_span(
        //     mul_ntt( uHat[i.into()].span(), s_ntt[i.into
        // ].span())
        // );
        let mut idx2 = 0;
        while idx2 < 256 {
            let sum = add_mod(*w.at(idx2), *product.at(idx2));
            w = set_array_at(w, idx2, sum);
            idx2 += 1;
        }
        i += 1;
    }
    // ntt inverse on w
    let w_inv = ntt(w.span());
    let mut final_w = ArrayTrait::new();
    i = 0;
    while i < 256{
        final_w.append(*v.at(i) - *w_inv.at(i));
        i += 1;
    }
    w = final_w;
    let compressed_w = compress(@w, 1);
    // print!("kpke_decrypt End\n");
    byte_encode(@compressed_w, 1) 
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

