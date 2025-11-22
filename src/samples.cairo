use crate::hashes::{SpongeContext, SHAKE128_DOMAIN, SHAKE128_RATE_BYTES};
use crate::hashes::keccak::keccak_sponge_init_context;
use crate::hashes::keccak::keccak_sponge_squeeze;
use crate::hashes::keccak::keccak_sponge_absorb;
use crate::utils::bytes_to_bits;
use crate::constants::{MLKEM_Q, MLKEM_Qu16, MLKEM_N};


/// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of 𝑇𝑞.
/// Output should be coefficients of the ntt of a polynomial in Z_q
pub fn sample_ntt(bytes: Span<u8>) -> Array<u16> {
    // print!("Running sample_ntt\n");
    let mut ctx : SpongeContext = keccak_sponge_init_context(SHAKE128_RATE_BYTES, SHAKE128_DOMAIN);
    ctx = keccak_sponge_absorb(ctx, bytes);
    
    let want_bytes : usize = 3 * 512;
    let (ctx, mut c) = keccak_sponge_squeeze(ctx, want_bytes);
    
    let mut j : usize = 0;
    let mut idx : usize = 0;
    let mut aHat : Array<u16> = ArrayTrait::new();

    while j < MLKEM_N && idx + 3 <= want_bytes {
        // let (ctx, mut c) = keccak_sponge_squeeze(ctx, 3); // this could be just made easier by grabbing say 3 * 512 bytes
        let c0 : u16 = c.pop_front().unwrap().into();
        let c1 : u16 = c.pop_front().unwrap().into();
        let c2 : u16 = c.pop_front().unwrap().into();
        idx +=3;

        let d1 : u16 = (c0 + MLKEM_N.try_into().unwrap() *( c1 % 16 ));
        let d2 : u16 = (c1/16 + 16 * c2);
    
        if( d1.into() < MLKEM_Q){
            aHat.append(d1);
            j += 1;
        }
        if( d2.into() < MLKEM_Q && j < MLKEM_N){
            aHat.append(d2);
            j += 1;
        }
    }
    // print!("Finished sample_ntt\n");
    aHat
}

///Takes a seed as input and outputs a pseudorandom sample from the distribution D𝜂(𝑅𝑞).
pub fn sample_poly_cbd(bytes: Span<u8>, eta: usize) -> Array<u16> {
    // print!("Running sample_poly_cbd\n");
    if( eta != 2 && eta != 3){
        panic!("Invalid eta value")
    }
    if( bytes.len() != 64 * eta.into()){
        panic!("Input B must be 64 * eta bytes")
    }

    let b = bytes_to_bits(bytes).span();
    let mut f : Array<u16> = ArrayTrait::new();

    let mut i = 0;
    while( i < MLKEM_N){
        let mut x : u16 = 0;
        let mut y : u16 = 0;

        // compute the two sums
        let mut j : usize = 0;
        while( j < eta){
            let mut idx : usize = (2 * eta * i + j).into();
            x += (*b.at(idx)).into();
            j += 1;
        }

        j = 0;
        while( j < eta){
            let mut idx : usize = (2 * eta * i + eta + j).into();
            y += (*b.at((idx))).into();
            j += 1;
        }
        f.append((x + MLKEM_Qu16 - y) % MLKEM_Qu16);
        i += 1;
    }
    // print!("Finished sample_poly_cbd\n");
    f
}
