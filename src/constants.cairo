// parameters for MLKEM
pub const MLKEM_Q: usize = 3329;
pub const MLKEM_Qu16: u16 = 3329;
pub const MLKEM_Qu64: u64 = 3329;
pub const MLKEM_N: usize = 256;
pub const MLKEM512_ETA1 : usize = 3; // generating s,e in KeyGen, y in Encrypt
pub const MLKEM_ETA : usize = 2; // all other etas
pub const MLKEM512_K: usize = 2;
pub const MLKEM768_K: usize = 3;
pub const MLKEM1024_K: usize = 4;

pub const MLKEM512_DV: usize = 4;
pub const MLKEM768_DV: usize = 4;
pub const MLKEM1024_DV: usize = 5;
pub const MLKEM512_DU: usize = 10;
pub const MLKEM768_DU: usize = 10;
pub const MLKEM1024_DU: usize = 11;

// lengths for keys
pub const MLKEM_SHARED_KEY_LEN : usize = 32;
pub const MLKEM512_ENCAPS_K: usize = 800;
pub const MLKEM768_ENCAPS_K: usize = 1184;
pub const MLKEM1024_ENCAPS_K: usize = 1568;
pub const MLKEM512_DECAPS_K: usize = 1632;
pub const MLKEM768_DECAPS_K: usize = 2400;
pub const MLKEM1024_DECAPS_K: usize = 3168;
pub const MLKEM512_CIPHER: usize = 768;
pub const MLKEM768_CIPHER: usize = 1088;
pub const MLKEM1024_CIPHER: usize = 1568;


// NTT constants for ML-KEM
// Modulus q = 3329
pub const MLKEM_Q_INVN: u16 = 3303;

// functions added to original file
pub fn get_zeta() -> Span<u16> {
    Zeta.span()
}

pub fn get_zeta2() -> Span<i16> {
    Zeta2.span()
}

const Zeta: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641, 
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
];

const Zeta2: [i16; 128] = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
];