use crate::mlkem::{MLKEM512_K, MLKEM512_ETA1, MLKEM512_DU, MLKEM512_DV, MLKEM512_ENCAPS_K, MLKEM512_DECAPS_K};
use crate::mlkem::keys;
use crate::mlkem::keyCipher;
use crate::mlkem::keys_init;
use crate::mlkem::keyCipher_init;
use crate::utils::concat_arrays;
use crate::hashes::H;
use crate::mlkem::kpke;

pub fn mlkem_key_gen_512_impl() -> keys{
    print!("Running mlkem_key_gen_512_impl\n");
    // internal needs two random 32byte seeds
    // let k = mlkem_key_gen_512_internal(@get_seed512(), @get_z512());
    let d = @get_seed512();
    let z = @get_z512();
    if(d.len() != 32_usize || z.len() != 32_usize){
        panic!("Seeds must be 32 bytes long");
    }

    // print!("Running mlkem_key_gen_512_internal\n");
    let mut kpkeKeys : keys = keys_init();
    let kpkeKeys = kpke::kpke_keygen(d, MLKEM512_K, MLKEM512_ETA1, MLKEM512_DU, MLKEM512_DV);
    let ekpke = kpkeKeys.ek;
    let dkpke = kpkeKeys.dk;
    
    // hex is sha3-256(ekpke), H function
    let hek = H(ekpke.clone());
    let dkpke_ekpke = concat_arrays(@dkpke, @ekpke);
    let tmp2 = concat_arrays(@dkpke_ekpke, @hek);

    let mut k : keys = keys_init();
    k.ek = ekpke;
    k.dk = concat_arrays(@tmp2, z);
    k.ek_len = MLKEM512_ENCAPS_K.try_into().unwrap();
    k.dk_len = MLKEM512_DECAPS_K.try_into().unwrap();
    // print!("Encapsulation key should be length: {}\n", MLKEM512_ENCAPS_K);
    // print!("Decapsulation key should be length: {}\n", MLKEM512_DECAPS_K);
    // print!("K has public key length: {} and secret key length: {}\n", k.ek.len(), k.dk.len());
    // print!("Struct says ek {} and dk {} bytes\n", k.ek_len, k.dk_len);
    // k
    print!("K has public key length: {} and secret key length: {}\n", k.ek.len(), k.dk.len());
    k
}

// pub fn mlkem_key_gen_512_impl() -> keys{
//     print!("Running mlkem_key_gen_512_impl\n");
//     // internal needs two random 32byte seeds
//     let k = mlkem_key_gen_512_internal(@get_seed512(), @get_z512());
//     print!("K has public key length: {} and secret key length: {}\n", k.ek.len(), k.dk.len());
//     k
// }


// pub fn mlkem_key_gen_768_impl() -> keys{
//     mlkem_internal::mlkem_key_gen_768_internal()
// }
// pub fn mlkem_key_gen_1024_impl() -> keys{
//     mlkem_internal::mlkem_key_gen_1024_internal()
// }

// pub fn mlkem_key_gen_512_internal( d : @Array<u8>, z : @Array<u8> ) -> keys{
//     if(d.len() != 32_usize || z.len() != 32_usize){
//         panic!("Seeds must be 32 bytes long");
//     }

//     // print!("Running mlkem_key_gen_512_internal\n");
//     let mut kpkeKeys : keys = keys_init();
//     let kpkeKeys = kpke::kpke_keygen(d, MLKEM512_K, MLKEM512_ETA1, MLKEM512_DU, MLKEM512_DV);
//     let ekpke = kpkeKeys.ek;
//     let dkpke = kpkeKeys.dk;
    
//     // hex is sha3-256(ekpke), H function
//     let hek = H(ekpke.clone());
//     let dkpke_ekpke = concat_arrays(@dkpke, @ekpke);
//     let tmp2 = concat_arrays(@dkpke_ekpke, @hek);

//     let mut k : keys = keys_init();
//     k.ek = ekpke;
//     k.dk = concat_arrays(@tmp2, z);
//     k.ek_len = MLKEM512_ENCAPS_K.try_into().unwrap();
//     k.dk_len = MLKEM512_DECAPS_K.try_into().unwrap();
//     // print!("Encapsulation key should be length: {}\n", MLKEM512_ENCAPS_K);
//     // print!("Decapsulation key should be length: {}\n", MLKEM512_DECAPS_K);
//     // print!("K has public key length: {} and secret key length: {}\n", k.ek.len(), k.dk.len());
//     // print!("Struct says ek {} and dk {} bytes\n", k.ek_len, k.dk_len);
//     k
// }



// values for testing purposes
fn get_seed512() -> Array<u8>{
//     let mut seed512 : [u8; 32] = [ 0xe1, 0xe3, 0x20, 0x68, 0x75, 0xe6, 0x7d, 0x7e, 0x81, 0x35,
// 0x37, 0x74, 0xfe, 0x90, 0x25, 0x03, 0x5b, 0x9b, 0x41, 0xa4, 0xa9, 0xf6,
// 0xec, 0x00, 0xb9, 0x1c, 0x60, 0x04, 0x42, 0xfd, 0x71, 0x7d ];
    let mut arr = ArrayTrait::new();
    arr.append(0xe1);
    arr.append(0xe3);
    arr.append(0x20);
    arr.append(0x68);
    arr.append(0x75);
    arr.append(0xe6);
    arr.append(0x7d);
    arr.append(0x7e);
    arr.append(0x81);
    arr.append(0x35);
    arr.append(0x37);
    arr.append(0x74);
    arr.append(0xfe);
    arr.append(0x90);
    arr.append(0x25);
    arr.append(0x03);
    arr.append(0x5b);
    arr.append(0x9b);
    arr.append(0x41);
    arr.append(0xa4);
    arr.append(0xa9);
    arr.append(0xf6);
    arr.append(0xec);
    arr.append(0x00);
    arr.append(0xb9);
    arr.append(0x1c);
    arr.append(0x60);
    arr.append(0x04);
    arr.append(0x42);
    arr.append(0xfd);
    arr.append(0x71);
    arr.append(0x7d);
    arr
}

fn get_z512() -> Array<u8>{
    // z512 = { 0xc6, 0xf5, 0x78, 0x5a, 0x6f, 0x2b, 0x42, 0xe8, 0x43, 0x22,
    // 0x8b, 0xe5, 0x3e, 0xb7, 0x68, 0xd6, 0x4c, 0x6f, 0x9d, 0x43, 0x55, 0xae, 0x95, 0xf0,
    // 0x83, 0xe5, 0x1e, 0xd5, 0x7c, 0x43, 0x73, 0x10 };
    let mut arr = ArrayTrait::new();
    arr.append(0xc6);
    arr.append(0xf5);
    arr.append(0x78);
    arr.append(0x5a);
    arr.append(0x6f);
    arr.append(0x2b);
    arr.append(0x42);
    arr.append(0xe8);
    arr.append(0x43);
    arr.append(0x22);
    arr.append(0x8b);
    arr.append(0xe5);
    arr.append(0x3e);
    arr.append(0xb7);
    arr.append(0x68);
    arr.append(0xd6);
    arr.append(0x4c);
    arr.append(0x6f);
    arr.append(0x9d);
    arr.append(0x43);
    arr.append(0x55);
    arr.append(0xae);
    arr.append(0x95);
    arr.append(0xf0);
    arr.append(0x83);
    arr.append(0xe5);
    arr.append(0x1e);
    arr.append(0xd5);
    arr.append(0x7c);
    arr.append(0x43);
    arr.append(0x73);
    arr.append(0x10);    
    arr
}

fn get_message512() -> Array<u8>{
    // message512 = { 0xa7, 0x41, 0xec, 0x20, 0x02, 0xbe, 0x6f, 0x4f, 0xa7,
    //     0x60, 0x37, 0xb7, 0xf0, 0x64, 0x4f, 0x83, 0x3f, 0xa8, 0x23, 0xe6, 0x30, 0x40, 0x1a,
    //     0x39, 0xd3, 0x24, 0x0c, 0x6e, 0x82, 0xa4, 0x30, 0xbb };
    let mut arr = ArrayTrait::new();
    arr.append(0xa7);
    arr.append(0x41);
    arr.append(0xec);
    arr.append(0x20);
    arr.append(0x02);
    arr.append(0xbe);
    arr.append(0x6f);
    arr.append(0x4f);
    arr.append(0xa7);
    arr.append(0x60);
    arr.append(0x37);
    arr.append(0xb7);
    arr.append(0xf0);
    arr.append(0x64);
    arr.append(0x4f);
    arr.append(0x83);
    arr.append(0x3f);
    arr.append(0xa8);
    arr.append(0x23);
    arr.append(0xe6);
    arr.append(0x30);
    arr.append(0x40);
    arr.append(0x1a);
    arr.append(0x39);
    arr.append(0xd3);
    arr.append(0x24);
    arr.append(0x0c);
    arr.append(0x6e);
    arr.append(0x82);
    arr.append(0xa4);
    arr.append(0x30);
    arr.append(0xbb);    
    arr
}