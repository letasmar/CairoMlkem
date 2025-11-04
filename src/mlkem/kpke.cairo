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
use crate::utils::set_array_at;
use crate::utils::append_n_zeroes;
use crate::utils::byte_encode;
use crate::utils::byte_decode;
use crate::utils::decompress;
use crate::utils::compress;
use crate::utils::concat_arrays;
use crate::utils::print_u16_span_dec;
use crate::utils::print_u8_span_hex;
use crate::mlkem::MLKEM_ETA;

/// d is random seed of 32 bytes, others are mlkem parameters
/// keys struct contains ek and dk as u8 arrays
pub fn kpke_keygen( d : Span<u8>, k : usize, eta : usize, du : usize, dv: usize) -> keys{
    print!("Running kpke_keygen\n");
    if(d.len() != 32_usize){
        panic!("Seed must be 32 bytes long");
    }
    
    // here perhaps d should be concatenated with k
    // G is SHA3-512
    let (rho, sigma ) = G(d.clone());
    let rho_span = rho.span();
    print!("Rho length: {}, Sigma length: {}\n", rho.len(), sigma.len());
    let mut big_n0 : u8 = 0;
    let mut i : u8 = 0;
    // generate matrix Ahat
    let mut Ahat : Array<Array<u16>> = generate_matrix(k, rho.clone());

    // print Ahat size
    println!("Ahat has {} rows", Ahat.len());
    // println!("Each row has {} columns", Ahat.at(0).len());

    // generate s vector 
    let (mut s, mut big_n1) = generate_vector( k, sigma.span(), eta, big_n0);


    //print s size
    println!("s has {} polynomials", s.len());
    // println!("Each polynomial has {} coefficients", s.at(0).len());

    // generate e vector
    let (mut e, mut big_n2) = generate_vector( k, sigma.span(), eta, big_n1);
    // print e size
    println!("e has {} polynomials", e.len());
    // println!("Each polynomial has {} coefficients", e.at(0).len());

    // run ntt on s and e each coordinate
    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let mut e_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in s.span(){
        s_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }
    for poly in e.span(){
        e_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }

    print!("s_ntt and e_ntt computed\n");

    // declare tHat
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();
    
    // compute t = As + e, first fill t with zeros
    i = 0;
    while i < k.try_into().unwrap(){
        // acc = tHat[i]
        let mut acc: Array<u16> = ArrayTrait::new(); 
        print!("Computing tHat polynomial {}\n", i);
        acc = append_n_zeroes(acc, 256, 0);

        let mut j : usize = 0;
        while j < k {
            let mut idx : usize = (i.into() * k + j).try_into().unwrap();
            let product : Array<u16> = array_from_span(
                multiply_ntt_kyber( Ahat[idx].span(), s_ntt[j.try_into().unwrap()].span())
            );
            let mut idx2 = 0;
            let mut tmp : Array<u16> = ArrayTrait::new();
            while idx2 < 256 {
                let sum = add_mod(*acc.at(idx2), *product.at(idx2));
                tmp.append(sum);
                // acc = set_array_at(acc, idx2, sum);
                idx2 += 1;
            }
            j += 1;
        }

        let mut idx : usize = 0;
        let mut tmp2 : Array<u16> = ArrayTrait::new();
        while idx < 256{
            // tHat[i][idx] = add_mod(tHat[i][idx], e_ntt[i]);
            let sum = add_mod(*acc.at(idx), *e_ntt.at(i.into()).at(idx));
            // acc = set_array_at(acc, idx, sum);
            tmp2.append(sum);
            idx += 1;
        }
        acc = tmp2;

        tHat.append(acc);
        i += 1;
    }
    // print tHat size
    println!("tHat has {} polynomials", tHat.len());
    // println!("Each polynomial has {} coefficients", tHat.at(0).len());


    //use  byte_encode to serialize ek and dk
    let mut key_pair = keys_init();
    // ek is tHat and rho combined
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
    // dk is s_ntt
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
    print!("Kpke KeyGen End eklength: {} dk length: {}\n", key_pair.ek_len, key_pair.dk_len);
    // if there is a bug, print out Ahat, s, e, tHat, rho and sigma
    println!("Debug info:");
    println!("Rho:");
    print_u8_span_hex(rho_span);
    println!("Sigma:");
    print_u8_span_hex(sigma.span());
        println!("Ahat:");
    for poly in Ahat{
        print_u16_span_dec(poly.span());
    }
    println!("s:");
    for poly in s.span(){
        print_u16_span_dec(poly.span());
    }
    println!("e:");
    for poly in e.span(){
        print_u16_span_dec(poly.span());
    }
    println!("tHat:");
    for poly in tHat.span(){
        print_u16_span_dec(poly.span());
    }
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
    print!("Running kpke_encrypt\n");
    // run bytedecode_12 k times to decode tHat and obtain rho from last 32 bytes of ek
    let mut i :usize = 0;
    let mut tHat : Array<Array<u16>> = ArrayTrait::new();

    // print out accessed indexes for debugging
    // println!("ek length: {}", ek_span.len());
    // println!("last byte index: {:x}", *ek_span.at(799));
    // println!("k value: {}", k);
    while i < k{
        let start_idx : usize = i.into() * 384;
        let end_idx : usize = start_idx + 384;
        let encoded_poly = ek_span.slice(start_idx, 384);
        // change everything to use spans
        tHat.append(byte_decode(encoded_poly, 12));
        // let enconded_poly = ek.clone().slice(start_idx, end_idx);
        // let tHat_poly = byte_decode(enconded_poly, 12);
        // print!("tHat polynomial {} decoded\n", i);
        i += 1;
    }

    // obtain rho
    let rho_start_idx : usize = k * 384;
    let rho = ek_span.slice(rho_start_idx, 32);

    // re-generate Ahat
    let Ahat : Array<Array<u16>> = generate_matrix(k, array_from_span(rho));
    // println!("Ahat regenerated with dimensions: {} x {}\n", Ahat.len(), Ahat.at(0).len());
    // print!("Ahat generated:\n");
    // for poly in Ahat.span(){
    //     print_u16_span_dec(poly.span());
    // }
    //generate y
    // println!("Generating y vector\n");
    let (mut y, mut big_n1) = generate_vector( k, r, eta, big_n);
    big_n = big_n1;
    // print!("Big N after y generation: {}\n", big_n);
    // print!("y generated:\n");
    // for poly in y.span(){
    //     print_u16_span_dec(poly.span());
    // }

    //generate e1
    // println!("Generating e1 vector\n");
    let (mut e1, mut big_n2) = generate_vector( k, r, eta2, big_n);
    big_n = big_n2;
    // print!("Big N after e1 generation: {}\n", big_n);
    // print!("e1 generated:\n");
    // for poly in e1.span(){
    //     print_u16_span_dec(poly.span());
    // }

    // sample e2, as a single vector
    // println!("Generating e2 vector\n");
    // println!("r is of length: {}\n", r.len());
    let e2 : Array<u16> = sample_poly_cbd(prfEta(eta2, r, big_n).span(), eta2);
    big_n += 1;
    // print!("Big N after e2 generation: {}\n", big_n);
    // print!("e2 generated:\n");
    // print_u16_span_dec(e2.span());

    // compute yhat - ntt of y
    i = 0;
    let mut y_ntt : Array<Array<u16>> = ArrayTrait::new();
    for poly in y{
        y_ntt.append(array_from_span(ntt_kyber(poly.span())));
    }

    // print!("y_ntt computed, start computing uHat\n");
    // compute u through ntt inverse
    let mut uHat : Array<Array<u16>> = ArrayTrait::new();
    i = 0;
    while i < k.try_into().unwrap(){
        // acc = uHat[i]
        let mut acc: Array<u16> = ArrayTrait::new();
        acc = append_n_zeroes(acc, 256, 0);
        let mut j : usize = 0;
        while j < k {
            let mut idx_1 : usize = (j * k + i.into());
            let Ahat_idx = Ahat.at(idx_1);
            let y_ntt_j = y_ntt.at(j);

            let product = multiply_ntt_kyber(Ahat_idx.span(), y_ntt_j.span());

            let mut idx2 = 0;
            let mut tmp : Array<u16> = ArrayTrait::new();
            while idx2 < 256 {
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
        while idx3 < 256{
            let e1_i = e1.at(i);
            let sum = add_mod(*acc_inv.at(idx3), *e1_i.at(idx3));
            acc2.append(sum);
            idx3 += 1;
        }
        uHat.append(acc2);
        i += 1
    }
    // compute mu through decompress
    // println!("Computing mu through decompress");
    let mu : Array<u16> = decompress(byte_decode(m, 1).span(), 1);
    // compute v
    // println!("Computing v");
    let mut v : Array<u16> = ArrayTrait::new();
    // first compute tHat * y_ntt
    let mut acc: Array<u16> = ArrayTrait::new();
    acc = append_n_zeroes(acc, 256, 0);
    i = 0;

    // println!("Computing tHat * y_ntt\n");
    while i < k.try_into().unwrap(){
        let tHat_i = tHat.at(i.into());
        let y_ntt_i = y_ntt.at(i.into());
        let product = multiply_ntt_kyber(tHat_i.span(), y_ntt_i.span());
        // let product : Array<u16> = array_from_span(
        //     mul_ntt( tHat[i.into()].span(), y_ntt[i.into()].span())
        // );
        // print!("Multiplying tHat[{}] and y_ntt[{}]\n", i, i);
        let mut idx2 = 0;
        let mut tmp : Array<u16> = ArrayTrait::new();
        while idx2 < 256 {
            let sum = add_mod(*acc.at(idx2), *product.at(idx2));
            tmp.append(sum);
            idx2 += 1;
        }
        acc = tmp;
        i += 1;
    }
    // println!("tHat * y_ntt computed\n");
    // println!("Computing ntt inverse on the accumulated value\n");
    // // ntt inverse on acc
    // print!("v before inverse:\n");
    // print_u16_span_dec(acc.span());
    let acc_inv = ntt_kyber_inv(acc.span());
    // add e2 and mu
    let mut idx3 = 0;
    // print!("Adding e2 and mu to acc_inv to compute v\n");
    // print!("v before adding (after ntt inverse):\n");
    // print_u16_span_dec(acc_inv);
    while idx3 < 256{
        let sum1 = add_mod(*acc_inv.at(idx3), *e2.at(idx3));
        let sum2 = add_mod(sum1, *mu.at(idx3));
        v.append(sum2);
        idx3 += 1;
    }
    // print!("v computed:\n");
    // print_u16_span_dec(v.span());

    // compute c1, c2
    let mut c1 : Array<u8> = ArrayTrait::new();
    let c2 : Array<u8> = byte_encode(compress(v.span(), dv).span(), dv);


    // //print uHat 
    // for uHat_i in uHat.span() {
    //     println!("uHat: ");
    //     for byte in uHat_i {
    //         println!("{:x}", *byte);
    //     }
    // }
    // print!("Computing c1\n");
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

    // // return concat_arrays(c1, c2)
    // print!("kpke_encrypt End\n");
    // // print out contents of c1 and c2 for debugging
    // println!("c1 length: {}", c1.len());
    // print_u8_span_hex(c1.span());
    // println!("c2 length: {}", c2.len());
    // print_u8_span_hex(c2.span());
    // println!("End of ciphertext debug info\n");
    array_from_span(concat_arrays(c1.span(), c2.span()))
}

pub fn kpke_decrypt(dk: Span<u8>, cipher: Span<u8>, k: usize, eta: usize, du: usize, dv: usize) -> Array<u8> {
    print!("Running kpke_decrypt\n");
    // get c_1 and c_2 from cipher
    let c1 = cipher.slice(0, 32 * k * du);
    let c2 = cipher.slice(32 * k * du, cipher.len() - (32 * k * du));

    let c1_bytes : usize = ((du * 256  + 7) / 8) * k;
    let c2_bytes : usize = ((dv * 256  + 7) / 8);

    // reconstruct uHat from c1
    print!("Reconstructing uHat from c1\n");
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
    //print uHat 
    for uHat_i in uHat.span() {
        println!("uHat: ");
        for byte in uHat_i {
            println!("arr.append({:x});", *byte);
        }
    }

    print!("reconstructing v from c2\n");
    // reconstruct v from c2
    let decoded_v = byte_decode(c2, dv);
    let v = decompress(decoded_v.span(), dv);

    // print v
    println!("v reconstructed (decaps):");
    print_u16_span_dec(v.span());

    let mut s_ntt : Array<Array<u16>> = ArrayTrait::new();
    let bytesPerPoly : usize = ((12 * 256 + 7) / 8);
    i = 0;
    while i < k {
        let offset : usize = i * bytesPerPoly;
        let encoded_poly = dk.slice(offset, bytesPerPoly);
        let decoded_poly = byte_decode(encoded_poly, 12);
        s_ntt.append(decoded_poly);
        i += 1;
    }
    // print s_ntt
    for s_ntt_i in s_ntt.span() {
        println!("s_ntt: ");
        for byte in s_ntt_i {
            println!("arr.append({:x});", *byte);
        }
    }

    // compute w
    print!("Computing w\n");
    let mut w : Array<u16> = ArrayTrait::new();

    w = append_n_zeroes(w, 256, 0);
    i = 0;
    while i < k.try_into().unwrap(){
        let uHat_i = uHat.at(i.into());
        let u_ntt_i = ntt_kyber(uHat_i.span());
        let s_ntt_i = s_ntt.at(i.into());
        let product = multiply_ntt_kyber(u_ntt_i, s_ntt_i.span());
        let mut idx2 = 0;
        let mut tmp : Array<u16> = ArrayTrait::new();
        while idx2 < 256 {
            let sum = add_mod(*w.at(idx2), *product.at(idx2));
            // w = set_array_at(w, idx2, sum);
            tmp.append(sum);
            idx2 += 1;
        }
        w = tmp;
        i += 1;
    }
    // ntt inverse on w
    // print before computintg w inverse
    println!("w before inverse(decaps):");
    print_u16_span_dec(w.span());
    print!("Computing w inverse\n");
    let w_inv = ntt_kyber_inv(w.span());
    // print w_inv
    println!("w_inv computed:\n");
    print_u16_span_dec(w_inv);
    let mut final_w = ArrayTrait::new();
    i = 0;
    while i < 256{
        final_w.append(sub_mod(*v.at(i), *w_inv.at(i)));
        i += 1;
    }
    w = final_w;
    let compressed_w = compress(w.span(), 1);
    print!("kpke_decrypt End\n");
    byte_encode(compressed_w.span(), 1) 
}

/// generate vector
pub fn generate_vector( k : usize, sigma : Span<u8>, eta : usize, mut big_n : u8) -> ( Array<Array<u16>>, u8 ){
    let mut v : Array<Array<u16>> = ArrayTrait::new();
    let mut i : u8= 0;
    // print!("Generating vector with {} polynomials\n", k);
    while i < k.try_into().unwrap(){
        let val = sample_poly_cbd(prfEta(eta, sigma, big_n).span(), eta.try_into().unwrap());
        // print_u16_span_dec(val.span());
        v.append(val);
        i += 1;
        big_n += 1;
        // print!("Polynomial {} generated\n", i);
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

