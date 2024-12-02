use core::fmt::Display;

use super::primitive::*;
use super::subtle::*;
use super::*;
use super::common;

/// Montgomery represented elements in GF(p)
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct GFpElement {
    pub limbs: [LIMB; 4],
}

impl From<[LIMB; 4]> for GFpElement {
    fn from(value: [LIMB; 4]) -> Self {
        let mut res = GFpElement { limbs: value };
        res.mul_assign(&GFpElement::RR);
        res
    }
}
impl Display for GFpElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{:016x}, {:016x}, {:016x}, {:016x}", self.limbs[0], self.limbs[1], self.limbs[2], self.limbs[3])
    }
}

impl GFpElement {
    pub const ZERO: GFpElement = GFpElement { limbs: [0; 4] };
    // Montgomery representation of [1] = R mod p
    pub const R: GFpElement = GFpElement {
        limbs: [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000],
    };

    // Montgomery representation of [R] = R^2 mod p
    pub const RR: GFpElement = GFpElement { limbs: [0; 4] };

    pub const PRIME: GFpElement = GFpElement {
        limbs: [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
    };

    /// self = a + b
    /// The result is in [0,p) if a+b < 2p.
    pub fn add(&mut self, a: &GFpElement, b: &GFpElement) -> &mut Self {
        let a = &a.limbs;
        let b = &b.limbs;

        let (t0, carry) = adc(a[0], b[0], 0);
        let (t1, carry) = adc(a[1], b[1], carry);
        let (t2, carry) = adc(a[2], b[2], carry);
        let (t3, carry) = adc(a[3], b[3], carry);

        self.set_conditional_sub_p(t0, t1, t2, t3, carry as u64)
        // self.limbs = add(&a.limbs, &b.limbs);
        // self
    }

    /// self += b
    pub fn add_assign(&mut self, a: &GFpElement) -> &mut Self {
        let a = &a.limbs;
        let b = &self.limbs;

        let (t0, carry) = adc(a[0], b[0], 0);
        let (t1, carry) = adc(a[1], b[1], carry);
        let (t2, carry) = adc(a[2], b[2], carry);
        let (t3, carry) = adc(a[3], b[3], carry);

        self.set_conditional_sub_p(t0, t1, t2, t3, carry as u64)
    }

    // self = a * b
    // Let b = b0 + b1*B + b2*B + b3*B, B = 2^64, then
    //   a * b / B^4
    // = ((((a*b0/B + a*b1)/B + a*b2)/B + a*b3)/B
    pub fn mul(&mut self, a: &GFpElement, b: &GFpElement) -> &mut Self {
        let a = &a.limbs;
        let b = &b.limbs;

        if !false {
            // 65MTPS
            let (acc0, carry) = mac(0, a[0], b[0], 0);
            let (acc1, carry) = mac(0, a[1], b[0], carry);
            let (acc2, carry) = mac(0, a[2], b[0], carry);
            let (acc3, acc4) = mac(0, a[3], b[0], carry);

            let (acc1, carry) = mac(acc1, a[0], b[1], 0);
            let (acc2, carry) = mac(acc2, a[1], b[1], carry);
            let (acc3, carry) = mac(acc3, a[2], b[1], carry);
            let (acc4, acc5) = mac(acc4, a[3], b[1], carry);

            let (acc2, carry) = mac(acc2, a[0], b[2], 0);
            let (acc3, carry) = mac(acc3, a[1], b[2], carry);
            let (acc4, carry) = mac(acc4, a[2], b[2], carry);
            let (acc5, acc6) = mac(acc5, a[3], b[2], carry);

            let (acc3, carry) = mac(acc3, a[0], b[3], 0);
            let (acc4, carry) = mac(acc4, a[1], b[3], carry);
            let (acc5, carry) = mac(acc5, a[2], b[3], carry);
            let (acc6, acc7) = mac(acc6, a[3], b[3], carry);

            montgomery_reduce(&mut self.limbs, acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7);
            self
        } else {
            // a * b[0]
            let (acc0, carry) = mac(0, a[0], b[0], 0);
            let (acc1, carry) = mac(0, a[1], b[0], carry);
            let (acc2, carry) = mac(0, a[2], b[0], carry);
            let (acc3, acc4) = mac(0, a[3], b[0], carry);
            let (acc1, acc2, acc3, acc4, acc5) = montgomery_reduce_narrow(acc0, acc1, acc2, acc3, acc4);
            // [acc1, acc2, acc3, acc4, acc5] = (a*b[0] + acc0*p)/B
            // <= ( (B^4-1)(B-1) + (B-1)p ) / B
            // = (B-1)(B^4 + p - 1)/B
            // < 2B^4
            // Thus acc5 <= 1.

            let (acc1, carry) = mac(acc1, a[0], b[1], 0);
            let (acc2, carry) = mac(acc2, a[1], b[1], carry);
            let (acc3, carry) = mac(acc3, a[2], b[1], carry);
            let (acc4, carry) = mac(acc4, a[3], b[1], carry);
            let (acc5, _) = adc(acc5, carry, 0);
            // the last adc has no carry:
            // [acc1, acc2, acc3, acc4, acc5] = (a*b[0] + x*p)/B + a*b[1]
            // = (a*(b[0] + b[1]*B) + x*p)/B
            // <= ((B^4-1)(B^2-1) + (B-1)^2)/B
            // = (B^6-B^4-2B+2)/B
            // < B^5
            let (acc2, acc3, acc4, acc5, acc6) = montgomery_reduce_narrow(acc1, acc2, acc3, acc4, acc5);

            let (acc2, carry) = mac(acc2, a[0], b[2], 0);
            let (acc3, carry) = mac(acc3, a[1], b[2], carry);
            let (acc4, carry) = mac(acc4, a[2], b[2], carry);
            let (acc5, carry) = mac(acc5, a[3], b[2], carry);
            let (acc6, _) = adc(acc6, carry, 0);
            // the last adc has no carry:
            // [acc2, acc3, acc4, acc5, acc6] = ((a*b[0] + x*p)/B + a*b[1] + x'*p)/B + a*b[2]
            // = (a*(b[0] + b[1]*B + b[2]*B^2) + x*p + x'*p*B )/B^2
            // <= ((B^4-1)(B^3-1) + (B-1)^2 + (B-1)^2B)/B^2
            // = (B^7-B^4-B^2-B+2)/B^2
            // < B^5
            let (acc3, acc4, acc5, acc6, acc7) = montgomery_reduce_narrow(acc2, acc3, acc4, acc5, acc6);

            let (acc3, carry) = mac(acc3, a[0], b[3], 0);
            let (acc4, carry) = mac(acc4, a[1], b[3], carry);
            let (acc5, carry) = mac(acc5, a[2], b[3], carry);
            let (acc6, carry) = mac(acc6, a[3], b[3], carry);
            let (acc7, _) = adc(acc7, carry, 0); // also no carry:
            let (acc4, acc5, acc6, acc7, carry) = montgomery_reduce_narrow(acc3, acc4, acc5, acc6, acc7);

            self.set_conditional_sub_p(acc4, acc5, acc6, acc7, carry)
        }
    }

    pub fn mul_assign(&mut self, b: &GFpElement) -> &mut Self {
        // *self = *GFpElement::default().mul(self,b);
        // self

        let a = &self.limbs;
        let b = &b.limbs;

        // a * b[0]
        let (acc0, carry) = mac(0, a[0], b[0], 0);
        let (acc1, carry) = mac(0, a[1], b[0], carry);
        let (acc2, carry) = mac(0, a[2], b[0], carry);
        let (acc3, acc4) = mac(0, a[3], b[0], carry);
        let (acc1, acc2, acc3, acc4, acc5) = montgomery_reduce_narrow(acc0, acc1, acc2, acc3, acc4);
        // [acc1, acc2, acc3, acc4, acc5] = a*b[0]/B

        let (acc1, carry) = mac(acc1, a[0], b[1], 0);
        let (acc2, carry) = mac(acc2, a[1], b[1], carry);
        let (acc3, carry) = mac(acc3, a[2], b[1], carry);
        let (acc4, carry) = mac(acc4, a[3], b[1], carry);
        let (acc5, _) = adc(acc5, carry, 0); // no carry, why/
        let (acc2, acc3, acc4, acc5, acc6) = montgomery_reduce_narrow(acc1, acc2, acc3, acc4, acc5);

        let (acc2, carry) = mac(acc2, a[0], b[2], 0);
        let (acc3, carry) = mac(acc3, a[1], b[2], carry);
        let (acc4, carry) = mac(acc4, a[2], b[2], carry);
        let (acc5, carry) = mac(acc5, a[3], b[2], carry);
        let (acc6, _) = adc(acc6, carry, 0);
        let (acc3, acc4, acc5, acc6, acc7) = montgomery_reduce_narrow(acc2, acc3, acc4, acc5, acc6);

        let (acc3, carry) = mac(acc3, a[0], b[3], 0);
        let (acc4, carry) = mac(acc4, a[1], b[3], carry);
        let (acc5, carry) = mac(acc5, a[2], b[3], carry);
        let (acc6, carry) = mac(acc6, a[3], b[3], carry);
        let (acc7, _) = adc(acc7, carry, 0);
        let (acc4, acc5, acc6, acc7, carry) = montgomery_reduce_narrow(acc3, acc4, acc5, acc6, acc7);

        self.set_conditional_sub_p(acc4, acc5, acc6, acc7, carry)
    }

    pub fn square(&mut self, b: &GFpElement) -> &mut Self {
        let b = &b.limbs;

        // [b[1], b[2], b[3]] * b[0]
        let (acc1, acc2) = mac(0, b[0], b[1], 0);
        let (acc2, acc3) = mac(0, b[0], b[2], acc2);
        let (acc3, acc4) = mac(0, b[0], b[3], acc3);

        // [b[2], b[3]] * b[1]
        let (acc3, t4) = mac(acc3, b[1], b[2], 0);
        let (acc4, acc5) = mac(acc4, b[1], b[3], t4);

        // b[3] * b[2]
        let (acc5, acc6) = mac(acc5, b[2], b[3], 0);

        // *2
        let (acc1, carry) = adc(acc1, acc1, 0);
        let (acc2, carry) = adc(acc2, acc2, carry);
        let (acc3, carry) = adc(acc3, acc3, carry);
        let (acc4, carry) = adc(acc4, acc4, carry);
        let (acc5, carry) = adc(acc5, acc5, carry);
        let (acc6, acc7) = adc(acc6, acc6, carry);

        // Now [0, acc1, acc2, acc3, acc4, acc5, acc6, acc7] = 2*sum (b[i] * b[j]), 0 <= i < j < 4

        // add the square parts
        let (acc0, t1) = mac(0, b[0], b[0], 0);
        let (t2, t3) = mac(0, b[1], b[1], 0);
        let (acc1, carry) = adc(acc1, t1, 0);
        let (acc2, carry) = adc(acc2, t2, carry);
        let (t3, _) = adc(t3, 0, carry);

        let (t4, t5) = mac(0, b[2], b[2], 0);
        let (acc3, carry) = adc(acc3, t3, 0);
        let (acc4, carry) = adc(acc4, t4, carry);
        let (t5, _) = adc(t5, 0, carry);

        let (t6, t7) = mac(0, b[3], b[3], 0);
        let (acc5, carry) = adc(acc5, t5, 0);
        let (acc6, carry) = adc(acc6, t6, carry);
        let (acc7, _) = adc(acc7 as u64, t7, carry);

        // let (acc0, t1) = mac(0, b[0], b[0], 0);
        // let (acc2, t3) = mac(acc2, b[1], b[1], 0);
        // let (acc4, t5) = mac(acc4, b[2], b[2], 0);
        // let (acc6, t7) = mac(acc6, b[3], b[3], 0);
        // let (acc1, carry ) = adc(acc1, t1, 0);
        // let (acc2, carry ) = adc(acc2, 0, carry);
        // let (acc3, carry ) = adc(acc3, t3, carry);
        // let (acc4, carry ) = adc(acc4, 0, carry);
        // let (acc5, carry ) = adc(acc5, t5, carry);
        // let (acc6, carry ) = adc(acc6, 0, carry);
        // let (acc7, _ ) = adc(acc7 as u64, t7, carry);

        montgomery_reduce(&mut self.limbs, acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7);
        self
    }

    pub fn square_assign(&mut self) -> &mut Self {
        let b = &self.limbs;

        // [b[1], b[2], b[3]] * b[0]
        let (acc1, acc2) = mac(0, b[0], b[1], 0);
        let (acc2, acc3) = mac(0, b[0], b[2], acc2);
        let (acc3, acc4) = mac(0, b[0], b[3], acc3);

        // [b[2], b[3]] * b[1]
        let (acc3, t4) = mac(acc3, b[1], b[2], 0);
        let (acc4, acc5) = mac(acc4, b[1], b[3], t4);

        // b[3] * b[2]
        let (acc5, acc6) = mac(acc5, b[2], b[3], 0);

        // *2
        let (acc1, carry) = adc(acc1, acc1, 0);
        let (acc2, carry) = adc(acc2, acc2, carry);
        let (acc3, carry) = adc(acc3, acc3, carry);
        let (acc4, carry) = adc(acc4, acc4, carry);
        let (acc5, carry) = adc(acc5, acc5, carry);
        let (acc6, acc7) = adc(acc6, acc6, carry);

        // Now [0, acc1, acc2, acc3, acc4, acc5, acc6, acc7] = 2*sum (b[i] * b[j]), 0 <= i < j < 4

        // add the square parts
        let (acc0, t1) = mac(0, b[0], b[0], 0);
        let (t2, t3) = mac(0, b[1], b[1], 0);
        let (acc1, carry) = adc(acc1, t1, 0);
        let (acc2, carry) = adc(acc2, t2, carry);
        let (t3, _) = adc(t3, 0, carry);

        let (t4, t5) = mac(0, b[2], b[2], 0);
        let (acc3, carry) = adc(acc3, t3, 0);
        let (acc4, carry) = adc(acc4, t4, carry);
        let (t5, _) = adc(t5, 0, carry);

        let (t6, t7) = mac(0, b[3], b[3], 0);
        let (acc5, carry) = adc(acc5, t5, 0);
        let (acc6, carry) = adc(acc6, t6, carry);
        let (acc7, _) = adc(acc7 as u64, t7, carry);

        // let (acc0, t1) = mac(0, b[0], b[0], 0);
        // let (acc2, t3) = mac(acc2, b[1], b[1], 0);
        // let (acc4, t5) = mac(acc4, b[2], b[2], 0);
        // let (acc6, t7) = mac(acc6, b[3], b[3], 0);
        // let (acc1, carry ) = adc(acc1, t1, 0);
        // let (acc2, carry ) = adc(acc2, 0, carry);
        // let (acc3, carry ) = adc(acc3, t3, carry);
        // let (acc4, carry ) = adc(acc4, 0, carry);
        // let (acc5, carry ) = adc(acc5, t5, carry);
        // let (acc6, carry ) = adc(acc6, 0, carry);
        // let (acc7, _ ) = adc(acc7 as u64, t7, carry);

        montgomery_reduce(&mut self.limbs, acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7);
        self
    }

    // set self = a-p if a >= p else a
    // The input should provide that [a0, a1, a2, a3, carry] < 2p,
    // otherwise the return > p.
    #[inline(always)]
    fn set_conditional_sub_p(&mut self, a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, carry: LIMB) -> &mut Self {
        let p = &Self::PRIME.limbs;
        let mut borrow;
        (self.limbs[0], borrow) = sbb(a0, p[0], 0);
        (self.limbs[1], borrow) = sbb(a1, p[1], borrow);
        (self.limbs[2], borrow) = sbb(a2, p[2], borrow);
        (self.limbs[3], borrow) = sbb(a3, p[3], borrow);
        (_, borrow) = sbb(carry, 0, borrow);

        conditional_assign(&mut self.limbs, &[a0, a1, a2, a3], borrow);
        self
    }
}

#[inline(always)]
fn add(out: &mut [LIMB; 4], a: &[LIMB; 4], b: &[LIMB; 4]) {
    let (t0, carry) = adc(a[0], b[0], 0);
    let (t1, carry) = adc(a[1], b[1], carry);
    let (t2, carry) = adc(a[2], b[2], carry);
    let (t3, carry) = adc(a[3], b[3], carry);

    conditional_sub_p(out, &[t0, t1, t2, t3, carry as LIMB])
}

#[inline(always)]
fn conditional_sub_p(out: &mut [LIMB; 4], a: &[LIMB; 5]) {
    let p = &GFpElement::PRIME.limbs;
    let mut borrow;

    (out[0], borrow) = sbb(a[0], p[0], 0);
    (out[1], borrow) = sbb(a[1], p[1], borrow);
    (out[2], borrow) = sbb(a[2], p[2], borrow);
    (out[3], borrow) = sbb(a[3], p[3], borrow);
    (_, borrow) = sbb(a[4], 0, borrow);

    conditional_assign(out, &[a[0], a[1], a[2], a[3]], borrow);
}

// returns [a0, a1, a2, a3, a4]/B.
// Note that return = [(a0 + a1*B + ... + a4*B^4) + a0*p]/B.
// For p = -1 mod B, thus the division is shifting right by 64.
// Note: The result may exceed the B^4.
#[inline(always)]
fn montgomery_reduce_narrow(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, a4: LIMB) -> (LIMB, LIMB, LIMB, LIMB, LIMB) {
    let (a1, carry) = adc(a1, a0, 0);
    let (a2, carry) = adc(a2, 0, carry);
    let (a3, carry) = adc(a3, 0, carry);
    let (a4, carry) = adc(a4, a0, carry);

    let lo = a0 << 32;
    let hi = a0 >> 32;

    let (a1, borrow) = sbb(a1, lo, 0);
    let (a2, borrow) = sbb(a2, hi, borrow);
    let (a3, borrow) = sbb(a3, lo, borrow);
    let (a4, borrow) = sbb(a4, hi, borrow);
    let (a5, _) = sbb(carry as u64, 0, borrow);

    (a1, a2, a3, a4, a5)
}

// returns a/B mod p = (a + a0*p)>>64
// Note that (a + a0*p) <= (B^4-1) + (B-1)^2 = B^3 + B - 2 < B^4.
#[inline(always)]
fn montgomery_reduce_limb(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB) -> (LIMB, LIMB, LIMB, LIMB) {
    let lo = a0 << 32;
    let hi = a0 >> 32;
    let (a1, carry) = adc(a1, a0, 0);
    let (a2, carry) = adc(a2, 0, carry);
    let (a3, carry) = adc(a3, 0, carry);
    let (a0, _) = adc(a0, 0, carry);

    let (a1, borrow) = sbb(a1, lo, 0);
    let (a2, borrow) = sbb(a2, hi, borrow);
    let (a3, borrow) = sbb(a3, lo, borrow);
    let (a0, _) = sbb(a0, hi, borrow);

    (a1, a2, a3, a0)
}

// returns a/R = a/(B^4) mod p
// The returned result < B^4, but can the result >= p?
#[inline(always)]
fn montgomery_reduce(out: &mut [LIMB; 4], a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, a4: LIMB, a5: LIMB, a6: LIMB, a7: LIMB) {
    let (a1, a2, a3, a0) = montgomery_reduce_limb(a0, a1, a2, a3);
    let (a2, a3, a4, a1) = montgomery_reduce_limb(a1, a2, a3, a4);
    let (a3, a4, a5, a2) = montgomery_reduce_limb(a2, a3, a4, a5);
    let (a4, a5, a6, a3) = montgomery_reduce_limb(a3, a4, a5, a6);

    // The same thing:
    // let (a1, a2, a3, a0) = montgomery_reduce_limb(a0, a1, a2, a3);
    // let (a2, a3, a0, a1) = montgomery_reduce_limb(a1, a2, a3, a0);
    // let (a3, a0, a1, a2) = montgomery_reduce_limb(a2, a3, a0, a1);
    // let (a0, a1, a2, a3) = montgomery_reduce_limb(a3, a0, a1, a2);

    add(out, &[a0, a1, a2, a3], &[a4, a5, a6, a7])
}

#[cfg(test)]
mod test {
    use super::*;
    use core::ops::{AddAssign, Mul, MulAssign};
    use hex_literal::hex;
    use num_bigint::*;
    use num_traits::*;
    use rand::Rng;
    use std::time::SystemTime;

    fn get_prime() -> BigUint {
        BigUint::from_bytes_be(hex!("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF").as_slice())
    }

    fn to_bigint(el: &[u64]) -> BigUint {
        let mut res = BigUint::default();
        let n = el.len();
        for i in 0..n {
            res <<= 64;
            res += el[n - 1 - i];
        }
        res
    }

    fn random() -> GFpElement {
        let mut rng = rand::thread_rng();
        GFpElement {
            limbs: [rng.gen(), rng.gen(), rng.gen(), rng.gen()],
        }
    }

    #[test]
    fn test_add() {
        let a = GFpElement {
            limbs: [0, 0xFFFFFFFF00000001, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
        };
        let b = GFpElement {
            limbs: [0xFFFFFFFFFFFFFFFD, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
        };
        let mut c = GFpElement { limbs: [0; 4] };
        c.add(&a, &b);
        assert_eq!(
            c,
            GFpElement {
                limbs: [0xFFFFFFFFFFFFFFFE, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF]
            }
        );
        c.add(&a, &GFpElement::PRIME);
        assert_eq!(c, a);
    }

    // 290 MTPS vs 530 MTPS(fincrypto) on M1.
    #[test]
    fn test_add_fuzzy() {
        for _ in 0..100000 {
            let a = random();
            let b = random();
            let mut c = GFpElement::default();
            c.add(&a, &b);
            let c = to_bigint(&c.limbs);

            let aa = to_bigint(&a.limbs);
            let bb = to_bigint(&b.limbs);
            let mut cc = aa + bb;
            let p = get_prime();
            if cc >= p {
                cc -= p;
            }

            assert_eq!(c, cc);
        }
    }

    #[test]
    fn test_montgomery_reduce_narrow() {
        let mut rng = rand::thread_rng();
        let p = get_prime();
        for _ in 0..100000 {
            let data: [u64; 5] = [rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()];
            let a = montgomery_reduce_narrow(data[0], data[1], data[2], data[3], data[4]);
            let a = to_bigint(&[a.0, a.1, a.2, a.3, a.4]);

            let aa = to_bigint(&data) + data[0] * &p;
            let bytes = aa.to_le_bytes();
            assert_eq!(bytes[..8], [0; 8]);
            let aa = aa >> 64;
            assert_eq!(a, aa);
        }
    }

    #[test]
    fn test_montgomery_reduce_limb() {
        let mut rng = rand::thread_rng();
        let mut binv = BigUint::from_slice(&[1]);
        binv <<= 64;
        binv = binv.modinv(&get_prime()).unwrap();
        // for _ in 0..100000000 {
        loop {
            let data: [u64; 4] = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
            let a = montgomery_reduce_limb(data[0], data[1], data[2], data[3]);
            let a = to_bigint(&[a.0, a.1, a.2, a.3]);
            let aa = (to_bigint(&data) * &binv) % get_prime();
            assert_eq!(a, aa);
        }
    }

    #[test]
    fn test_montgomery_reduce() {
        let mut rng = rand::thread_rng();
        let mut rinv = BigUint::from_slice(&[1]);
        rinv <<= 256;
        rinv = rinv.modinv(&get_prime()).unwrap();

        // for _ in 0..1000000 {
        let mut i: u128 = 0;
        loop {
            if i % (100 * 1000 * 1000) == 0 {
                println!("test: {}亿", i / (100 * 1000 * 1000));
            }
            i += 1;
            let data: [u64; 8] = [rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()];
            let mut a = [0; 4];
            montgomery_reduce(&mut a, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
            let a = to_bigint(&a);

            let aa = (to_bigint(&data) * &rinv) % get_prime();
            assert_eq!(a, aa);
            if a != aa {
                println!("data: {:?}", data);
                println!("aa  : {:?}", aa);
                println!("a   : {:?}", a);
                break;
            }
        }
    }

    #[test]
    fn test_mul() {
        let a = GFpElement { limbs: [1, 0, 0, 0] };
        let b = GFpElement {
            limbs: [0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000],
        };
        let wanted = GFpElement { limbs: [1, 0, 0, 0] };
        let mut c = GFpElement::default();
        c.mul(&a, &b);
        println!("{}", c);

        assert_eq!(c.limbs, wanted.limbs);
    }

    #[test]
    fn test_mul_fuzz() {
        let rinv = to_bigint(&GFpElement::R.limbs).modinv(&get_prime()).unwrap();
        for _i in 0..10000000 {
            let a = random();
            let b = random();
            let mut c = GFpElement::default();
            c.mul(&a, &b); // a*b/R
            let c = to_bigint(&c.limbs);

            let aa = to_bigint(&a.limbs);
            let bb = to_bigint(&b.limbs);
            let cc = aa * bb * &rinv % get_prime();
            assert_eq!(c, cc);
        }
    }

    #[test]
    fn test_sqr_fuzz() {
        let rinv = to_bigint(&GFpElement::R.limbs).modinv(&get_prime()).unwrap();
        for _i in 0..10000000 {
            let a = random();
            let mut c = GFpElement::default();
            c.square(&a);
            let c = to_bigint(&c.limbs);

            let aa = to_bigint(&a.limbs);
            let cc = &aa * &aa * &rinv % get_prime();
            assert_eq!(c, cc);
        }
    }

    extern crate test;
    // cargo test --release --package opengm_crypto --lib -- sm2::gfp::test::test_mul_speed --exact --show-output
    #[test]
    fn test_add_speed() {
        // 614 MTPS vs 72 MTPS(fincrypto) on M1.
        let a = GFpElement {
            limbs: [0xFFFFFFFFFFFFFFFE, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
        };
        let b = a;
        let mut c = a;

        let loops = 1000000000u64;
        let now = SystemTime::now();
        for _ in 0..loops {
            test::black_box(c.add(&a, &b));
        }
        let elapsed = now.elapsed().unwrap().as_nanos();
        println!("{:?}", c);
        println!("{} MTPS", (loops as u128 * 1000000000) / (1000000 * elapsed));
    }

    #[test]
    fn test_mul_speed() {
        // 62 MTPS vs 72 MTPS(fincrypto) on M1.
        let a = GFpElement {
            limbs: [0xFFFFFFFFFFFFFFFE, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
        };
        let b = a;
        let mut c = a;

        let loops = 1000000000u64;
        let now = SystemTime::now();
        for _ in 0..loops {
            // test::black_box(c.mul_assign(&b));
            test::black_box(c.mul(&a, &b));
        }
        let elapsed = now.elapsed().unwrap().as_nanos();
        println!("{:?}", c);
        println!("{} MTPS", (loops as u128 * 1000000000) / (1000000 * elapsed));
    }

    #[test]
    fn test_sqr_speed() {
        // 62 MTPS vs 72 MTPS(fincrypto) on M1.
        let mut a = random();
        let mut c = a;

        let loops = 1000000000u64;
        let now = SystemTime::now();
        for _ in 0..loops / 2 {
            test::black_box(c.square(&a));
            test::black_box(a.square(&c));
            // test::black_box(c.square_assign());
        }
        let elapsed = now.elapsed().unwrap().as_nanos();
        println!("{:?}", c);
        println!("{} MTPS", (loops as u128 * 1000000000) / (1000000 * elapsed));
    }
}
