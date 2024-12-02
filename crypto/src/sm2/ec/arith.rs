use subtle::*;
use super::primitive::*;
use super::*;
/// set dst = a if c == 1
/// remain unchanged if c == 0
/// other c panic.
#[inline(always)]
pub fn conditional_assign4(dst0: &mut LIMB, dst1: &mut LIMB, dst2: &mut LIMB, dst3: &mut LIMB, a0: &LIMB, a1: &LIMB, a2: &LIMB, a3: &LIMB, c: u8) {
    let c = Choice::from(c);
    dst0.conditional_assign(&a0, c);
    dst1.conditional_assign(&a1, c);
    dst2.conditional_assign(&a2, c);
    dst3.conditional_assign(&a3, c);
}

#[inline(always)]
pub fn constant_eq(rhs: &[LIMB;4], lhs: &[LIMB; 4]) -> bool {
    rhs.ct_eq(lhs).into()
}

#[inline(always)]
pub fn mul256(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, b0: LIMB, b1: LIMB, b2: LIMB, b3: LIMB) -> (LIMB, LIMB, LIMB, LIMB, LIMB, LIMB, LIMB, LIMB) {
    let (acc0, carry) = mac(0, a0, b0, 0);
    let (acc1, carry) = mac(0, a1, b0, carry);
    let (acc2, carry) = mac(0, a2, b0, carry);
    let (acc3, acc4) = mac(0, a3, b0, carry);

    let (acc1, carry) = mac(acc1, a0, b1, 0);
    let (acc2, carry) = mac(acc2, a1, b1, carry);
    let (acc3, carry) = mac(acc3, a2, b1, carry);
    let (acc4, acc5) = mac(acc4, a3, b1, carry);

    let (acc2, carry) = mac(acc2, a0, b2, 0);
    let (acc3, carry) = mac(acc3, a1, b2, carry);
    let (acc4, carry) = mac(acc4, a2, b2, carry);
    let (acc5, acc6) = mac(acc5, a3, b2, carry);

    let (acc3, carry) = mac(acc3, a0, b3, 0);
    let (acc4, carry) = mac(acc4, a1, b3, carry);
    let (acc5, carry) = mac(acc5, a2, b3, carry);
    let (acc6, acc7) = mac(acc6, a3, b3, carry);
    (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7)
}

#[inline(always)]
pub fn square256(b0: LIMB, b1: LIMB, b2: LIMB, b3: LIMB) -> (LIMB, LIMB, LIMB, LIMB, LIMB, LIMB, LIMB, LIMB) {
    // [b[1], b[2], b[3]] * b[0]
    let (acc1, acc2) = mac(0, b0, b1, 0);
    let (acc2, acc3) = mac(0, b0, b2, acc2);
    let (acc3, acc4) = mac(0, b0, b3, acc3);

    // [b[2], b[3]] * b[1]
    let (acc3, t4) = mac(acc3, b1, b2, 0);
    let (acc4, acc5) = mac(acc4, b1, b3, t4);

    // b3 * b2
    let (acc5, acc6) = mac(acc5, b2, b3, 0);

    // *2
    let (acc1, carry) = adc(acc1, acc1, false);
    let (acc2, carry) = adc(acc2, acc2, carry);
    let (acc3, carry) = adc(acc3, acc3, carry);
    let (acc4, carry) = adc(acc4, acc4, carry);
    let (acc5, carry) = adc(acc5, acc5, carry);
    let (acc6, acc7) = adc(acc6, acc6, carry);

    // Now [0, acc1, acc2, acc3, acc4, acc5, acc6, acc7] = 2*sum (b[i] * b[j]), 0 <= i < j < 4

    // add the square parts
    let (acc0, t1) = mac(0, b0, b0, 0);
    let (t2, t3) = mac(0, b1, b1, 0);
    let (acc1, carry) = adc(acc1, t1, false);
    let (acc2, carry) = adc(acc2, t2, carry);
    let (t3, _) = adc(t3, 0, carry);

    let (t4, t5) = mac(0, b2, b2, 0);
    let (acc3, carry) = adc(acc3, t3, false);
    let (acc4, carry) = adc(acc4, t4, carry);
    let (t5, _) = adc(t5, 0, carry);

    let (t6, t7) = mac(0, b3, b3, 0);
    let (acc5, carry) = adc(acc5, t5, false);
    let (acc6, carry) = adc(acc6, t6, carry);
    let (acc7, _) = adc(acc7 as u64, t7, carry);
    // let (acc0, t1) = mac(0, b0, b0, 0);
    // let (acc2, t3) = mac(acc2, b1, b1, 0);
    // let (acc4, t5) = mac(acc4, b2, b2, 0);
    // let (acc6, t7) = mac(acc6, b3, b3, 0);
    // let (acc1, carry ) = adc(acc1, t1, 0);
    // let (acc2, carry ) = adc(acc2, 0, carry);
    // let (acc3, carry ) = adc(acc3, t3, carry);
    // let (acc4, carry ) = adc(acc4, 0, carry);
    // let (acc5, carry ) = adc(acc5, t5, carry);
    // let (acc6, carry ) = adc(acc6, 0, carry);
    // let (acc7, _ ) = adc(acc7 as u64, t7, carry);

    (acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7)
}

#[inline(always)]
pub fn add256(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, b0: LIMB, b1: LIMB, b2: LIMB, b3: LIMB) -> (LIMB, LIMB, LIMB, LIMB, bool) {
    let (acc0, carry) = adc(a0, b0, false);
    let (acc1, carry) = adc(a1, b1, carry);
    let (acc2, carry) = adc(a2, b2, carry);
    let (acc3, carry) = adc(a3, b3, carry);
    (acc0, acc1, acc2, acc3, carry)
}

#[inline(always)]
pub fn sub256(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, b0: LIMB, b1: LIMB, b2: LIMB, b3: LIMB) -> (LIMB, LIMB, LIMB, LIMB, bool) {
    let (acc0, borrow) = sbb(a0, b0, false);
    let (acc1, borrow) = sbb(a1, b1, borrow);
    let (acc2, borrow) = sbb(a2, b2, borrow);
    let (acc3, borrow) = sbb(a3, b3, borrow);
    (acc0, acc1, acc2, acc3, borrow)
}


// set self = a-m if a >= m else a
// The input should provide that [a0, a1, a2, a3, carry] < 2m,
// otherwise the return >= m.
#[inline(always)]
pub fn sub256_conditional(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, carry: LIMB, m0: LIMB, m1: LIMB, m2: LIMB, m3: LIMB) -> (LIMB, LIMB, LIMB, LIMB) {
    let (mut acc0, borrow) = sbb(a0, m0, false);
    let (mut acc1, borrow) = sbb(a1, m1, borrow);
    let (mut acc2, borrow) = sbb(a2, m2, borrow);
    let (mut acc3, borrow) = sbb(a3, m3, borrow);
    let (_, borrow) = sbb(carry, 0, borrow);

    let c =  Choice::from(borrow as u8);
    acc0.conditional_assign(&a0, c);
    acc1.conditional_assign(&a1, c);
    acc2.conditional_assign(&a2, c);
    acc3.conditional_assign(&a3, c);

    (acc0, acc1, acc2, acc3)
}

/// Returns a + m iff borrow = 1. 
/// borrow mush be 0 or 1, otherwise the result is undefined.
/// The input should provide that [a0, a1, a2, a3, borrow] = -borrow*B^4 + a0 + a1*B + a2*B^2 + a3*B^3 >= -m.
#[inline(always)]
pub fn add256_conditional(a0: LIMB, a1: LIMB, a2: LIMB, a3: LIMB, borrow: bool, m0: LIMB, m1: LIMB, m2: LIMB, m3: LIMB) -> (LIMB, LIMB, LIMB, LIMB) {
    // if borrow = 1, mask = 0xff..ff(-1), otherwise mask = 0.
    let mask =  (!(borrow as LIMB)).wrapping_add(1); 

    let (acc0, carry) = adc(a0, m0 & mask , false);
    let (acc1, carry) = adc(a1, m1 & mask, carry);
    let (acc2, carry) = adc(a2, m2 & mask, carry);
    let (acc3, _) = adc(a3, m3 & mask, carry);
    
    (acc0, acc1, acc2, acc3)
}
