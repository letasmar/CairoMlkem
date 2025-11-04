use crate::utils::from_u8Array_to_WordArray_Le;
use crate::utils::from_WordArray_to_u8array_Le;
use crate::utils::set_array_at;
use crate::utils::append_n_zeroes;
use crate::utils::{Word64, Word64WordOperations};
use crate::hashes::SpongeContext;

/// Keccak sponge hash function
/// # Arguments
/// * `input` - Input data as a Span<u8>
/// * `rate_bytes` - Rate in bytes
/// * `domain` - Domain separation byte
/// * `out_len` - Desired output length in bytes
/// # Returns
/// * `Array<u8>` - Output hash as an Array<u8>
pub fn keccak_sponge_hash(input: Span<u8>, rate_bytes : usize, domain : u8, out_len: usize) -> Array<u8> {
    let mut ctx = keccak_sponge_init_context(rate_bytes, domain);
    // Absorb phase
    ctx = keccak_sponge_absorb( ctx, input);
    // Squeeze phase
    let (_ctx, output) = keccak_sponge_squeeze(ctx, out_len);
    output
}

/// Keccak sponge squeeze function
/// # Arguments
/// * `ctx` - Sponge context after absorption
/// * `out_len` - Desired output length in bytes
/// # Returns
/// * `(SpongeContext, Array<u8>)` - Updated context and output data
pub fn keccak_sponge_squeeze(mut ctx: SpongeContext, out_len: usize) -> (SpongeContext, Array<u8>){
    let mut output = ArrayTrait::new();
    let mut output_remaining = out_len;
    let mut output_pos: usize = 0;
    let mut block_size = 0;
    let rate_bytes = ctx.rate_bytes;
    let mut state = ctx.state;
    let piln = get_keccak_piln();
    let rotc = get_keccak_rot();
    let rndc = get_keccak_rndc();
    while output_remaining > 0 {
        // Calculate output block size as a minimum of rate_bytes and output_remaining
        if output_remaining < rate_bytes {
            block_size = output_remaining;
        } else {
            block_size = rate_bytes;
        }
        
        // Copy state to output
        let mut j: usize = 0;
        while j < block_size {
            output.append(*state.at(j));
            j += 1;
        }
        
        output_remaining -= block_size;
        output_pos += block_size;
        
        // If more output needed, apply permutation
        if output_remaining > 0 {
            state = keccak_f_state_permute(state.span(), piln, rotc, rndc);
            output_pos = 0;
        }
    }
    ctx.state = state;
    
    (ctx, output)
}

/// Initializes the Keccak sponge context
/// # Arguments
/// * `rate_bytes` - Rate in bytes
/// * `domain` - Domain separation byte
/// # Returns
/// * `SpongeContext` - Initialized sponge context with zeroed state
pub fn keccak_sponge_init_context(rate_bytes: usize, domain: u8) -> SpongeContext {
    let mut state: Array<u8> = ArrayTrait::new();
    state = append_n_zeroes(state, 200, 0_u8);
    
    SpongeContext {
        state: state,
        rate_bytes: rate_bytes,
        domain: domain,
    }
}

/// Keccak sponge absorb function
/// # Arguments
/// * `ctx` - Sponge context
/// * `input` - Input data as a Span<u8>
/// # Returns
/// * `SpongeContext` - Updated sponge context after absorption
pub fn keccak_sponge_absorb(mut ctx: SpongeContext, input: Span<u8>) -> SpongeContext{
    let rate_bytes = ctx.rate_bytes;
    let mut state = ctx.state;
    let domain = ctx.domain;
    let mut input_pos: usize = 0;
    let input_len = input.len();
    let mut block_size: usize = 0;
    let piln = get_keccak_piln();
    let rotc = get_keccak_rot();
    let rndc = get_keccak_rndc();
    // Absorb phase
    while input_pos < input_len {
        // Calculate block size
        if input_len - input_pos < rate_bytes {
            block_size = input_len - input_pos;
        } else {
            block_size = rate_bytes;
        }
        
        // XOR input block into state
        let mut j: usize = 0;
        while j < block_size {
            let state_val = *state.at(j);
            let input_val = *input.at(input_pos + j);
            state = set_array_at(state, j, state_val ^ input_val);
            // state[j] = state_val ^ input_val;
            j += 1;
        }
        
        input_pos += block_size;
        
        // If block is complete, apply permutation
        if block_size == rate_bytes {
            state = keccak_f_state_permute(state.span(), piln, rotc, rndc);
        }
    }
    
    // Padding phase
    let current_pos = input_len % rate_bytes;
    
    // Add domain suffix
    let state_val = *state.at(current_pos);
    state = set_array_at(state, current_pos, state_val ^ domain);
    // state[current_pos] = state_val ^ domain;
    
    // Check if we need extra block for padding
    if (domain & 0x80) != 0 && current_pos == (rate_bytes - 1) {
        state = keccak_f_state_permute(state.span(), piln, rotc, rndc);
    }
    
    // Add final padding bit
    let last_pos = rate_bytes - 1;
    let last_val = *state.at(last_pos);
    state = set_array_at(state, last_pos, last_val ^ 0x80);
    
    // Final permutation
    state = keccak_f_state_permute(state.span(), piln, rotc, rndc);
    let mut res = keccak_sponge_init_context(rate_bytes, domain);
    res.state = state;
    res
}

pub fn keccak_f_state_permute(state : Span<u8>, piln : Span<Word64>, rotc : Span<Word64>, rndc : Span<Word64>) -> Array<u8>{
    let mut tmp = from_u8Array_to_WordArray_Le(state);
    let mut tmp2 = keccak_f(tmp, piln, rotc, rndc);
    from_WordArray_to_u8array_Le(tmp2.span())
}

fn keccak_f(mut s: Array<Word64> , piln : Span<Word64>, rotc : Span<Word64>, rndc : Span<Word64>) -> Array<Word64>{

    let mut round = 0;
    while round < 24{
        // theta
        let mut bc: Array<Word64> = ArrayTrait::new();
        let mut i = 0;
        while i < 5 {
            bc.append( *s[i] ^ *s[i + 5] ^ *s[i + 10] ^ *s[i + 15] ^ *s[i + 20]);
            i+=1;
        }
        i = 0;
        while i < 5 {
            let t = *bc[(i + 4) % 5] ^ (*bc[(i + 1) % 5]).rotl(1);
            let mut j = 0;
            while j < 5 {
                // s[j*5 + i] = s[j*5 + i] ^ t;
                // s = set_array_at(s, j*5+1, *s[j*5 + i] ^ t);
                let lane = *s[j*5 + i];        // get the element first
                let new_val = lane ^ t;        // compute
                s = set_array_at(s, j*5 + i, new_val); // update
                j+= 1;
            }
            i+= 1;
        }
        //rho & pi
        let mut t = *s[1];
        i = 0;
        while i < 24 {
            let j = *piln[i];
            let j64 : u64 = j.into();
            let tmp = s[j64.try_into().unwrap()];
            s = set_array_at(s, j64.try_into().unwrap(), t.rotl((*rotc[i]).into()));
            t = *tmp;
            i += 1;
        }
        // Chi
        let mut j = 0;
        while j < 5 {
        // for j in 0..5 {
            let a0 = *s[j*5 + 0];
            let a1 = *s[j*5 + 1];
            let a2 = *s[j*5 + 2];
            let a3 = *s[j*5 + 3];
            let a4 = *s[j*5 + 4];
            s = set_array_at(s, j*5 + 0, a0 ^ ((~a1) & a2));
            s = set_array_at(s, j*5 + 1, a1 ^ ((~a2) & a3));
            s = set_array_at(s, j*5 + 2, a2 ^ ((~a3) & a4));
            s = set_array_at(s, j*5 + 3, a3 ^ ((~a4) & a0));
            s = set_array_at(s, j*5 + 4, a4 ^ ((~a0) & a1));
            j += 1;
        }
        // iota
        let iota : Word64 = *rndc[round];
        // s = set_array_at(s, 0, *s[0] ^ iota);
        let new_val = *s[0]^iota;
        // let new_val = lane ^ t;
        s = set_array_at(s, 0, new_val);

        round += 1;
    }
    let res = s;
    res
}

// Return the rotation constants
fn get_keccak_rot() -> Span<Word64> {
    let mut rot: Array<Word64> = ArrayTrait::new();
    rot.append(Word64 { data: 0x01 });
    rot.append(Word64 { data: 0x03 });
    rot.append(Word64 { data: 0x06 });
    rot.append(Word64 { data: 0x0A });
    rot.append(Word64 { data: 0x0F });
    rot.append(Word64 { data: 0x15 });
    rot.append(Word64 { data: 0x1C });
    rot.append(Word64 { data: 0x24 });
    rot.append(Word64 { data: 0x2D });
    rot.append(Word64 { data: 0x37 });
    rot.append(Word64 { data: 0x02 });
    rot.append(Word64 { data: 0x0E });
    rot.append(Word64 { data: 0x1B });
    rot.append(Word64 { data: 0x29 });
    rot.append(Word64 { data: 0x38 });
    rot.append(Word64 { data: 0x08 });
    rot.append(Word64 { data: 0x19 });
    rot.append(Word64 { data: 0x2B });
    rot.append(Word64 { data: 0x3E });
    rot.append(Word64 { data: 0x12 });
    rot.append(Word64 { data: 0x27 });
    rot.append(Word64 { data: 0x3D });
    rot.append(Word64 { data: 0x14 });
    rot.append(Word64 { data: 0x2C });
    rot.append(Word64 { data: 0x3C });
    rot.span()
}

// Return the Pi Lane indices
fn get_keccak_piln() -> Span<Word64> {
    let mut piln: Array<Word64> = ArrayTrait::new();
    piln.append(Word64 { data: 10 });
    piln.append(Word64 { data: 7 });
    piln.append(Word64 { data: 11 });
    piln.append(Word64 { data: 17 });
    piln.append(Word64 { data: 18 });
    piln.append(Word64 { data: 3 });
    piln.append(Word64 { data: 5 });
    piln.append(Word64 { data: 16 });
    piln.append(Word64 { data: 8 });
    piln.append(Word64 { data: 21 });
    piln.append(Word64 { data: 24 });
    piln.append(Word64 { data: 4 });
    piln.append(Word64 { data: 15 });
    piln.append(Word64 { data: 23 });
    piln.append(Word64 { data: 19 });
    piln.append(Word64 { data: 13 });
    piln.append(Word64 { data: 12 });
    piln.append(Word64 { data: 2 });
    piln.append(Word64 { data: 20 });
    piln.append(Word64 { data: 14 });
    piln.append(Word64 { data: 22 });
    piln.append(Word64 { data: 9 });
    piln.append(Word64 { data: 6 });
    piln.append(Word64 { data: 1 });
    piln.span()
}

// Returns the Keccak round constants
fn get_keccak_rndc() -> Span<Word64> {
    let mut rndc: Array<Word64> = ArrayTrait::new();
    rndc.append(Word64 { data: 0x0000000000000001 });
    rndc.append(Word64 { data: 0x0000000000008082 });
    rndc.append(Word64 { data: 0x800000000000808a });
    rndc.append(Word64 { data: 0x8000000080008000 });
    rndc.append(Word64 { data: 0x000000000000808b });
    rndc.append(Word64 { data: 0x0000000080000001 });
    rndc.append(Word64 { data: 0x8000000080008081 });
    rndc.append(Word64 { data: 0x8000000000008009 });
    rndc.append(Word64 { data: 0x000000000000008a });
    rndc.append(Word64 { data: 0x0000000000000088 });
    rndc.append(Word64 { data: 0x0000000080008009 });
    rndc.append(Word64 { data: 0x000000008000000a });
    rndc.append(Word64 { data: 0x000000008000808b });
    rndc.append(Word64 { data: 0x800000000000008b });
    rndc.append(Word64 { data: 0x8000000000008089 });
    rndc.append(Word64 { data: 0x8000000000008003 });
    rndc.append(Word64 { data: 0x8000000000008002 });
    rndc.append(Word64 { data: 0x8000000000000080 });
    rndc.append(Word64 { data: 0x000000000000800a });
    rndc.append(Word64 { data: 0x800000008000000a });
    rndc.append(Word64 { data: 0x8000000080008081 });
    rndc.append(Word64 { data: 0x8000000000008080 });
    rndc.append(Word64 { data: 0x0000000080000001 });
    rndc.append(Word64 { data: 0x8000000080008008 });
    rndc.span()
}
