use crate::constants::{get_zeta, get_zeta2, MLKEM_Q_INVN, MLKEM_N};
use crate::zq::{add_mod, mul_mod, sub_mod, mul_mod_signed};
use crate::utils::{array_from_span, set_array_at};


// Compute the NTT of a polynomial in Kyber parameters
pub fn ntt_kyber(mut f : Span<u16>) -> Span<u16> {
    // print!("Computing NTT Kyber\n");
    let mut fHat = array_from_span(f);
    let mut i : u8 = 1;
    let zeta = get_zeta(MLKEM_N);

    let mut len : usize = MLKEM_N/2;
    while(len >= 2){
        let mut start : usize = 0;
        while(start < MLKEM_N){
            let zeta_i = *zeta.at(i.into());
            i += 1;

            let mut j : usize = start;
            while(j < start + len){
                let idx : u32 = j+ len;
                let fHat_at_idx = *fHat.at(idx);
                let fHat_at_j = *fHat.at(j.into());

                let t : u16 = mul_mod(zeta_i, fHat_at_idx);
                fHat = set_array_at(fHat, idx, sub_mod(fHat_at_j, t));
                fHat = set_array_at(fHat, j, add_mod(fHat_at_j, t));
                j += 1;
            }
            start = start + 2 * len;
        }

        len = len / 2;
    }
    // print!("Completed NTT Kyber\n");
    fHat.span()
}

pub fn ntt_kyber_inv(mut fHat : Span<u16>) -> Span<u16> {

    // print!("Computing Inverse NTT Kyber\n");
    let mut f = array_from_span(fHat);
    let mut i : usize = MLKEM_N/2 - 1;
    let zeta = get_zeta(MLKEM_N);

    let mut len : usize = 2;
    while(len <= MLKEM_N/2){
        let mut start : usize = 0;
        while(start < MLKEM_N){
            let zeta_i = *zeta.at(i);
            i -= 1;

            let mut j : usize = start;
            while(j < start + len){
                let t : u16 = *f.at(j);
                let idx : u32 = j + len;
                let f_at_idx = *f.at(idx);

                let temp = sub_mod(f_at_idx, t);
                f = set_array_at(f, j, add_mod(t, f_at_idx));
                f = set_array_at(f, idx, mul_mod(zeta_i, temp));
                j += 1;
            }
            start = start + 2 * len;
        }

        len = len * 2;
    }
    // multiply by n^-1
    let n_inv = MLKEM_Q_INVN;
    let mut f_mul : Array<u16> = ArrayTrait::new();
    for val in @f{
        f_mul.append(mul_mod(*val, n_inv));
    }
    // print!("Completed Inverse NTT Kyber\n");
    f_mul.span()
}

fn basecase_multiply_ntt_kyber( a0 : u16, a1 : u16, b0 : u16, b1: u16, z2 : i16) -> (u16, u16) {
    let t0 = mul_mod(a0, b0);
    let t1 = mul_mod_signed(mul_mod(a1, b1).try_into().unwrap(), z2);
    let c0 = add_mod(t0, t1);
    let c1 = add_mod(mul_mod(a0, b1), mul_mod(a1, b0));
    (c0, c1)
}

pub fn multiply_ntt_kyber( f: Span<u16>, g: Span<u16>) -> Span<u16> {
    let zeta2 = get_zeta2(MLKEM_N);

    let mut hhat : Array<u16> = ArrayTrait::new();
    let mut i : u32 = 0;
    while(i < MLKEM_N/2){
        let (c0, c1) = basecase_multiply_ntt_kyber(*f.at(2*i), *f.at(2*i+1), *g.at(2*i), *g.at(2*i+1), *zeta2.at(i));
        hhat.append(c0);
        hhat.append(c1);
        i += 1;
    }
    hhat.span()
}