mod opt_math;
mod sha512;
mod wrapping_math;
mod hashes;
use crate::sha512::Word64;

#[executable]
fn main(){
    let mut a : Array<u8> = ArrayTrait::new();
    let b = hashes::sha3_256(@a);
    for element in b{
        println!("{}", element);
    }
    // println!("Code ran!");
}