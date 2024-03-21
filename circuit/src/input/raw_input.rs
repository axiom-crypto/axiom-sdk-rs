use axiom_codec::{utils::native::encode_addr_to_field, HiLo};
use axiom_query::axiom_eth::Field;
use ethers::types::{Address, H256};

use super::flatten::FixLenVec;

pub trait RawInput<F: Field> {
    type FEType<T: Copy>;
    fn convert(&self) -> Self::FEType<F>;
}

impl<F: Field> RawInput<F> for usize {
    type FEType<T: Copy> = T;
    fn convert(&self) -> Self::FEType<F> {
        F::from_u128(*self as u128)
    }
}

impl<F: Field> RawInput<F> for u32 {
    type FEType<T: Copy> = T;
    fn convert(&self) -> Self::FEType<F> {
        F::from(*self as u64)
    }
}

impl<F: Field> RawInput<F> for u64 {
    type FEType<T: Copy> = T;
    fn convert(&self) -> Self::FEType<F> {
        F::from(*self)
    }
}

impl<F: Field> RawInput<F> for u128 {
    type FEType<T: Copy> = T;
    fn convert(&self) -> Self::FEType<F> {
        F::from_u128(*self)
    }
}

impl<F: Field> RawInput<F> for H256 {
    type FEType<T: Copy> = HiLo<T>;
    fn convert(&self) -> Self::FEType<F> {
        HiLo::from(*self)
    }
}

impl<F: Field> RawInput<F> for Address {
    type FEType<T: Copy> = T;
    fn convert(&self) -> Self::FEType<F> {
        encode_addr_to_field(self)
    }
}

impl<F: Field, const N: usize> RawInput<F> for [u8; N] {
    type FEType<T: Copy> = [T; N];
    fn convert(&self) -> Self::FEType<F> {
        let mut res = [F::ZERO; N];
        for i in 0..N {
            res[i] = F::from(self[i] as u64);
        }
        res
    }
}

impl<F: Field, const N: usize> RawInput<F> for [u64; N] {
    type FEType<T: Copy> = [T; N];
    fn convert(&self) -> Self::FEType<F> {
        let mut res = [F::ZERO; N];
        for i in 0..N {
            res[i] = F::from(self[i]);
        }
        res
    }
}

impl<F: Field, const N: usize> RawInput<F> for [usize; N] {
    type FEType<T: Copy> = [T; N];
    fn convert(&self) -> Self::FEType<F> {
        let mut res = [F::ZERO; N];
        for i in 0..N {
            res[i] = F::from(self[i] as u64);
        }
        res
    }
}

impl<F: Field, const N: usize> RawInput<F> for FixLenVec<usize, N> {
    type FEType<T: Copy> = [T; N];
    fn convert(&self) -> Self::FEType<F> {
        let mut res = [F::ZERO; N];
        for (i, item) in res.iter_mut().enumerate().take(N) {
            *item = F::from(self.0[i] as u64);
        }
        res
    }
}
