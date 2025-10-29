mod opt_math;
mod wrapping_math;
mod hashes;
mod utils;
use crate::hashes::{sha3_256, sha3_512, shake128_xof, shake256_xof};

#[executable]
fn main(){
    let mut a : Array<u8> = ArrayTrait::new();
    a.append('a');
    a.append('b');
    a.append('c');
    let mut b = a.clone();
    let mut c = a.clone();
    let mut d = a.clone();
    let mut res : Array<Array<u8>> = ArrayTrait::new();

    res.append(sha3_256(a));
    res.append(sha3_512(b));
    res.append(shake128_xof(c, 32));
    res.append(shake256_xof(d, 32));
    for element in res.clone(){
        println!("{} characters", element.len());
        for e in element{
            print!("{:x}",e);
        }
        println!("");
    }
    println!("Code ran!");
}