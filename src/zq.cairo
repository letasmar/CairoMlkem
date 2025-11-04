// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
//! accessed Oct 29, 2025
//! url: https://github.com/starkware-bitcoin/s2morrow/blob/master/packages/falcon/src/zq.cairo
//! the following code has been modified to change the modulus Q from 12289 to 3329:

use core::num::traits::CheckedAdd;
use crate::constants::{MLKEM_Q, MLKEM_Qu16, MLKEM_Qu64};

/// Add two values modulo Q
pub fn add_mod(a: u16, b: u16) -> u16 {
    a.checked_add(b).expect('u16 add overflow') % MLKEM_Qu16
}

/// Subtract two values modulo Q
pub fn sub_mod(a: u16, b: u16) -> u16 {
    (a.checked_add(MLKEM_Qu16).expect('u16 + Q overflow') - b) % MLKEM_Qu16
}

/// Multiply two values modulo Q
pub fn mul_mod(a: u16, b: u16) -> u16 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    let res = (a * b) % MLKEM_Q;
    res.try_into().unwrap()
}

/// Multiply three values modulo Q
pub fn mul3_mod(a: u16, b: u16, c: u16) -> u16 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    let c: u64 = c.into();
    let res = (a * b * c) % MLKEM_Qu64;
    res.try_into().unwrap()
}

/// Multiply signed modulo Q
pub fn mul_mod_signed(a: i16, b: i16) -> u16 {
    let mut res: i32 = (a.into() * b.into());
    res = res % (MLKEM_Qu16.into());
    if res < 0 {
        res += MLKEM_Qu16.into();
    }
    res.try_into().unwrap()
}