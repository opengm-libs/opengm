#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::{
    aligned64, sm3::{util::*, BLOCK_SIZE}
};
use core::mem::transmute;

const MASK: __m512i = unsafe {transmute([
    0x00000000ffffffffu64,0,
    0x00000000ffffffff,0,
    0x00000000ffffffff,0,
    0x00000000ffffffff,0,
    ])};
const ZERO: __m512i = unsafe {transmute([0u64;8])};

// msg_sched computes the next 3 Ws.
// in:
// w0: x, W0,  x,   x   ...
// w1: x, W3,  W2,  W1
// w2: x, W6,  W5,  W4
// w3: x, W9,  W8,  W7
// w4: x, W12, W11, W10
// w5: x, W15, W14, W13
// out:
// w1: x, W3,  x,   x
// w2: x, W6,  W5,  W4
// w3: x, W9,  W8,  W7
// w4: x, W12, W11, W10
// w5: x, W15, W14, W13
// w0: x, W18, W17, W16
#[inline(always)]
unsafe fn msg_sched(w0: __m512i, w1: __m512i, w2: __m512i, w3: __m512i, w4: __m512i, w5: __m512i) -> __m512i {
    let t0 = _mm512_mask_shuffle_epi32(ZERO, 0x1111, w0, 0b10101010);
    let tt = _mm512_bslli_epi128(w1, 4); // 0,w2, W1,0
    let t0 = _mm512_xor_si512(t0, tt); // t0: X, W2, W1, W0
 
    let t1 = _mm512_mask_shuffle_epi32(ZERO, 0x1111, w1, 0b10101010); // 0,0,0, W3
    let tt = _mm512_bslli_epi128(w2, 4); ////t1: w6,  W5, W4, 0
    let t1 = _mm512_xor_si512(t1, tt); // t1: x,  W5, W4, W3

    let t2 = _mm512_xor_si512(w3, t0); // t2: W0 ^ W7
    let t3 = _mm512_rol_epi32(w5, 15); // t3: W13 <<< 15
    let t2 = _mm512_xor_si512(t2, t3); // t2: W0 ^ W7 ^ (W13 <<< 15)
    let t0 = _mm512_rol_epi32(t2, 15);
    let t3 = _mm512_rol_epi32(t2, 23);
    let t2 = _mm512_xor_si512(t2, _mm512_xor_si512(t0, t3)); // t2: P1(W0 ^ W7 ^ (W13 <<< 15))
    let t2 = _mm512_xor_si512(t2, _mm512_rol_epi32(t1, 7)); // t2: P1(W0 ^ W7 ^ (W13 <<< 15)) ^ (W3 <<< 7)
    _mm512_xor_si512(t2, w4) // w0: x, W18, W17, W16
}


use crate::sm3::generic::round;

use super::compress_amd64_sse2;

// 调整端序
// t0 = _mm_shuffle_epi8(t0, flp);
// 将t0中保存的4个32比特的整数转换端序
const FLIP32: __m512i = unsafe {
    transmute([
        0x0405060700010203u64, 0x0C0D0E0F08090A0B, 
        0x1415161710111213, 0x1C1D1E1F18191A1B, 
        0x2425262720212223, 0x2C2D2E2F28292A2B, 
        0x3435363730313233, 0x3C3D3E3F38393A3B
    ])
};



#[inline(always)]
pub(crate) fn compress_amd64_avx512<'a>(iv: &mut [u32; 8], p: &'a [u8]) -> &'a [u8] {
    let mut p = p;
    p = unsafe { unsafe_compress4_amd64_avx512(iv, p) };
    while p.len() >= BLOCK_SIZE{
        p = compress_amd64_sse2(iv, p);
    }
    p
}

// precomputed message expansions
// W, X, Y, Z
// w:
// x, x, w0, x | x, x, X0, x | x, x, Y0, x | x, x, Z0, x |
// w1, w2, w3, x | x1, x2, x3, x | y1, y2, y3, x| z1, z2, z3,x|
// ....
#[inline(always)]
const fn get_w(w: &[u32], k: usize, i: usize) -> u32 {
    let row = (i + 2) / 3;
    let col = k * 4 + (i + 2) % 3;
    w[row * 16 + col]
}

// compress 4 blocks of p, i.e., 256 bytes.
#[target_feature(enable = "ssse3", enable = "sse2", enable = "avx512f", enable = "avx512vl", enable = "avx512bw")]
unsafe fn unsafe_compress4_amd64_avx512<'a>(iv: &mut [u32; 8], p: &'a [u8]) -> &'a [u8] {
    unsafe {
        // 要浪费1/4空间, ceil(68/3) * 16
        let w = &mut aligned64!([0u32; { 24 * 16 }]);

        const BLOCK_SIZE4: usize = 4 * BLOCK_SIZE;
        let (chunks, tail) = p.as_chunks::<BLOCK_SIZE4>();
        for chunk in chunks {
            let t0 = _mm512_loadu_si512(chunk.as_ptr() as *const i32);
            let t1 = _mm512_loadu_si512(chunk.as_ptr().offset(64) as *const i32);
            let t2 = _mm512_loadu_si512(chunk.as_ptr().offset(128) as *const i32);
            let t3 = _mm512_loadu_si512(chunk.as_ptr().offset(192) as *const i32);
            let t0 = _mm512_shuffle_epi8(t0, FLIP32);
            let t1 = _mm512_shuffle_epi8(t1, FLIP32);
            let t2 = _mm512_shuffle_epi8(t2, FLIP32);
            let t3 = _mm512_shuffle_epi8(t3, FLIP32);

            // transpose (4 * 128)
            // t0: 3  2  1  0
            // t1: 7  6  5  4
            // t2: 11 10 9  8
            // t3: 15 14 13 12
            let v0 = _mm512_shuffle_i32x4(t0, t2, 0b10001000); // 10 8  2  0
            let v1 = _mm512_shuffle_i32x4(t1, t3, 0b10001000); // 14 12 6  4
            let v2 = _mm512_shuffle_i32x4(t0, t2, 0b11011101); // 11 9  3  1
            let v3 = _mm512_shuffle_i32x4(t1, t3, 0b11011101); // 15 13 7  5

            let t0 = _mm512_shuffle_i32x4(v0, v1, 0b10001000); // 12 4  8  0
            let t1 = _mm512_shuffle_i32x4(v2, v3, 0b10001000); // 13 5  9  1
            let t2 = _mm512_shuffle_i32x4(v0, v1, 0b11011101); // 14 6  10 2
            let t3 = _mm512_shuffle_i32x4(v2, v3, 0b11011101); // 15 7  11 3

            let v0 = _mm512_shuffle_i32x4(t0, t0, 0b11011000); // 12 8  4  0
            let v1 = _mm512_shuffle_i32x4(t1, t1, 0b11011000); // 13 9  5  1
            let v2 = _mm512_shuffle_i32x4(t2, t2, 0b11011000); // 14 10 6  2
            let v3 = _mm512_shuffle_i32x4(t3, t3, 0b11011000); // 15 11 7  3

            // 转换为3个w
            //        3     2       1      0
            //  v0: W[3],  W[2],  W[1],  W[0] ...
            //  v1: W[7],  W[6],  W[5],  W[4] ...
            //  v2: W[11], W[10], W[9],  W[8] ...
            //  v3: W[15], W[14], W[13], W[12] ...
            //  =>
            // w0: x, W0,  x,   x   ...
            // w1: x, W3,  W2,  W1
            // w2: x, W6,  W5,  W4
            // w3: x, W9,  W8,  W7
            // w4: x, W12, W11, W10
            // w5: x, W15, W14, W13
            let mut w0 = _mm512_shuffle_epi32(v0, 0b11001111); // w0: x, W0,  x,   x
            let mut w1 = _mm512_shuffle_epi32(v0, 0b11111001); // w1: x, W3,  W2,  W1
            let mut w2 = v1; // w2: x, W6,  W5,  W4

            let t1 = _mm512_bsrli_epi128(v1, 12); // 0, 0, 0,  W7
            let t2 = _mm512_bslli_epi128(v2, 4); //  x, w9, W8, 0
            let mut w3 = _mm512_xor_si512(t1, t2);// w3: 0, w9, W8,  W7

            let t1 = _mm512_bsrli_epi128(v2, 8); // 0, 0, W11, W10
            let t2 = _mm512_bslli_epi128(v3, 8); //  x, w12, 0, 0
            let mut w4 = _mm512_xor_si512(t1, t2);// w3: x, W12, W11, W10

            let mut w5 = _mm512_shuffle_epi32(v3, 0b11111001); // w5: x, W15, W14, W13

            _mm512_store_si512(w.as_ptr() as *mut i32, w0);
            _mm512_store_si512(w.as_ptr().offset(16) as *mut i32, w1);
            _mm512_store_si512(w.as_ptr().offset(32) as *mut i32, w2);
            _mm512_store_si512(w.as_ptr().offset(48) as *mut i32, w3);
            _mm512_store_si512(w.as_ptr().offset(64) as *mut i32, w4);
            _mm512_store_si512(w.as_ptr().offset(80) as *mut i32, w5);

            let mut offset = 96;
            // message schedule
            for _ in 0..3 {
                w0 = msg_sched(w0, w1, w2, w3, w4, w5);
                w1 = msg_sched(w1, w2, w3, w4, w5, w0);
                w2 = msg_sched(w2, w3, w4, w5, w0, w1);
                w3 = msg_sched(w3, w4, w5, w0, w1, w2);
                w4 = msg_sched(w4, w5, w0, w1, w2, w3);
                w5 = msg_sched(w5, w0, w1, w2, w3, w4);
                _mm512_store_si512(w.as_ptr().offset(offset) as *mut i32, w0);
                _mm512_store_si512(w.as_ptr().offset(offset + 16) as *mut i32, w1);
                _mm512_store_si512(w.as_ptr().offset(offset + 32) as *mut i32, w2);
                _mm512_store_si512(w.as_ptr().offset(offset + 48) as *mut i32, w3);
                _mm512_store_si512(w.as_ptr().offset(offset + 64) as *mut i32, w4);
                _mm512_store_si512(w.as_ptr().offset(offset + 80) as *mut i32, w5);
                offset += 96;
            }

            for k in 0..4 {
                let mut a = iv[0];
                let mut b = iv[1];
                let mut c = iv[2];
                let mut d = iv[3];
                let mut e = iv[4];
                let mut f = iv[5];
                let mut g = iv[6];
                let mut h = iv[7];

                round!(0, get_w(w, k, 0), get_w(w, k, 0)^get_w(w, k, 4), a, b, c, d, e, f, g, h, ff0, gg0);
                round!(1, get_w(w, k, 1), get_w(w, k, 1)^get_w(w, k, 4 + 1), d, a, b, c, h, e, f, g, ff0, gg0);
                round!(2, get_w(w, k, 2), get_w(w, k, 2)^get_w(w, k, 4 + 2), c, d, a, b, g, h, e, f, ff0, gg0);
                round!(3, get_w(w, k, 3), get_w(w, k, 3)^get_w(w, k, 4 + 3), b, c, d, a, f, g, h, e, ff0, gg0);
                round!(4, get_w(w, k, 4), get_w(w, k, 4)^get_w(w, k, 4 + 4), a, b, c, d, e, f, g, h, ff0, gg0);
                round!(5, get_w(w, k, 5), get_w(w, k, 5)^get_w(w, k, 4 + 5), d, a, b, c, h, e, f, g, ff0, gg0);
                round!(6, get_w(w, k, 6), get_w(w, k, 6)^get_w(w, k, 4 + 6), c, d, a, b, g, h, e, f, ff0, gg0);
                round!(7, get_w(w, k, 7), get_w(w, k, 7)^get_w(w, k, 4 + 7), b, c, d, a, f, g, h, e, ff0, gg0);
                round!(8, get_w(w, k, 8), get_w(w, k, 8)^get_w(w, k, 4 + 8), a, b, c, d, e, f, g, h, ff0, gg0);
                round!(9, get_w(w, k, 9), get_w(w, k, 9)^get_w(w, k, 4 + 9), d, a, b, c, h, e, f, g, ff0, gg0);
                round!(10, get_w(w, k, 10), get_w(w, k, 10)^get_w(w, k, 4 + 10), c, d, a, b, g, h, e, f, ff0, gg0);
                round!(11, get_w(w, k, 11), get_w(w, k, 11)^get_w(w, k, 4 + 11), b, c, d, a, f, g, h, e, ff0, gg0);
                round!(12, get_w(w, k, 12), get_w(w, k, 12)^get_w(w, k, 4 + 12), a, b, c, d, e, f, g, h, ff0, gg0);
                round!(13, get_w(w, k, 13), get_w(w, k, 13)^get_w(w, k, 4 + 13), d, a, b, c, h, e, f, g, ff0, gg0);
                round!(14, get_w(w, k, 14), get_w(w, k, 14)^get_w(w, k, 4 + 14), c, d, a, b, g, h, e, f, ff0, gg0);
                round!(15, get_w(w, k, 15), get_w(w, k, 15)^get_w(w, k, 4 + 15), b, c, d, a, f, g, h, e, ff0, gg0);
                round!(16, get_w(w, k, 16), get_w(w, k, 16)^get_w(w, k, 4+16), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(17, get_w(w, k, 17), get_w(w, k, 17)^get_w(w, k, 4+17), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(18, get_w(w, k, 18), get_w(w, k, 18)^get_w(w, k, 4+18), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(19, get_w(w, k, 19), get_w(w, k, 19)^get_w(w, k, 4+19), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(20, get_w(w, k, 20), get_w(w, k, 20)^get_w(w, k, 4+20), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(21, get_w(w, k, 21), get_w(w, k, 21)^get_w(w, k, 4+21), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(22, get_w(w, k, 22), get_w(w, k, 22)^get_w(w, k, 4+22), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(23, get_w(w, k, 23), get_w(w, k, 23)^get_w(w, k, 4+23), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(24, get_w(w, k, 24), get_w(w, k, 24)^get_w(w, k, 4+24), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(25, get_w(w, k, 25), get_w(w, k, 25)^get_w(w, k, 4+25), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(26, get_w(w, k, 26), get_w(w, k, 26)^get_w(w, k, 4+26), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(27, get_w(w, k, 27), get_w(w, k, 27)^get_w(w, k, 4+27), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(28, get_w(w, k, 28), get_w(w, k, 28)^get_w(w, k, 4+28), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(29, get_w(w, k, 29), get_w(w, k, 29)^get_w(w, k, 4+29), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(30, get_w(w, k, 30), get_w(w, k, 30)^get_w(w, k, 4+30), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(31, get_w(w, k, 31), get_w(w, k, 31)^get_w(w, k, 4+31), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(32, get_w(w, k, 32), get_w(w, k, 32)^get_w(w, k, 4+32), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(33, get_w(w, k, 33), get_w(w, k, 33)^get_w(w, k, 4+33), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(34, get_w(w, k, 34), get_w(w, k, 34)^get_w(w, k, 4+34), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(35, get_w(w, k, 35), get_w(w, k, 35)^get_w(w, k, 4+35), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(36, get_w(w, k, 36), get_w(w, k, 36)^get_w(w, k, 4+36), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(37, get_w(w, k, 37), get_w(w, k, 37)^get_w(w, k, 4+37), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(38, get_w(w, k, 38), get_w(w, k, 38)^get_w(w, k, 4+38), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(39, get_w(w, k, 39), get_w(w, k, 39)^get_w(w, k, 4+39), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(40, get_w(w, k, 40), get_w(w, k, 40)^get_w(w, k, 4+40), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(41, get_w(w, k, 41), get_w(w, k, 41)^get_w(w, k, 4+41), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(42, get_w(w, k, 42), get_w(w, k, 42)^get_w(w, k, 4+42), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(43, get_w(w, k, 43), get_w(w, k, 43)^get_w(w, k, 4+43), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(44, get_w(w, k, 44), get_w(w, k, 44)^get_w(w, k, 4+44), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(45, get_w(w, k, 45), get_w(w, k, 45)^get_w(w, k, 4+45), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(46, get_w(w, k, 46), get_w(w, k, 46)^get_w(w, k, 4+46), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(47, get_w(w, k, 47), get_w(w, k, 47)^get_w(w, k, 4+47), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(48, get_w(w, k, 48), get_w(w, k, 48)^get_w(w, k, 4+48), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(49, get_w(w, k, 49), get_w(w, k, 49)^get_w(w, k, 4+49), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(50, get_w(w, k, 50), get_w(w, k, 50)^get_w(w, k, 4+50), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(51, get_w(w, k, 51), get_w(w, k, 51)^get_w(w, k, 4+51), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(52, get_w(w, k, 52), get_w(w, k, 52)^get_w(w, k, 4+52), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(53, get_w(w, k, 53), get_w(w, k, 53)^get_w(w, k, 4+53), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(54, get_w(w, k, 54), get_w(w, k, 54)^get_w(w, k, 4+54), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(55, get_w(w, k, 55), get_w(w, k, 55)^get_w(w, k, 4+55), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(56, get_w(w, k, 56), get_w(w, k, 56)^get_w(w, k, 4+56), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(57, get_w(w, k, 57), get_w(w, k, 57)^get_w(w, k, 4+57), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(58, get_w(w, k, 58), get_w(w, k, 58)^get_w(w, k, 4+58), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(59, get_w(w, k, 59), get_w(w, k, 59)^get_w(w, k, 4+59), b, c, d, a, f, g, h, e, ff1, gg1);
                round!(60, get_w(w, k, 60), get_w(w, k, 60)^get_w(w, k, 4+60), a, b, c, d, e, f, g, h, ff1, gg1);
                round!(61, get_w(w, k, 61), get_w(w, k, 61)^get_w(w, k, 4+61), d, a, b, c, h, e, f, g, ff1, gg1);
                round!(62, get_w(w, k, 62), get_w(w, k, 62)^get_w(w, k, 4+62), c, d, a, b, g, h, e, f, ff1, gg1);
                round!(63, get_w(w, k, 63), get_w(w, k, 63)^get_w(w, k, 4+63), b, c, d, a, f, g, h, e, ff1, gg1);

                iv[0] ^= a;
                iv[1] ^= b;
                iv[2] ^= c;
                iv[3] ^= d;
                iv[4] ^= e;
                iv[5] ^= f;
                iv[6] ^= g;
                iv[7] ^= h;
            }
        }
        tail
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};

    use crate::sm3::amd64::compress_generic;

    use super::*;
    #[test]
    fn test_compress() {
        let mut iv1 = [
            0x7380166fu32,
            0x4914b2b9,
            0x172442d7,
            0xda8a0600,
            0xa96f30bc,
            0x163138aa,
            0xe38dee4d,
            0xb0fb0e4e,
        ];
        let mut iv2 = iv1.clone();
        let mut p = [0u8; 64 * 4];
        thread_rng().fill_bytes(&mut p);
        compress_amd64_avx512(&mut iv1, p.as_slice());
        compress_generic(&mut iv2, p.as_slice());
        assert_eq!(iv1, iv2);
    }
}
