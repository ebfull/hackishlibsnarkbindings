use super::initialize;
use libc::c_char;
use std::ops::{Mul,Add,Sub,Neg};
use std::fmt;
use std::ffi::CString;
use rustc_serialize::{Encodable,Encoder,Decodable,Decoder};

type Bigint = [u64; 4];

extern "C" {
    fn tinysnark_fieldt_zero() -> Bigint;
    fn tinysnark_fieldt_one() -> Bigint;
    fn tinysnark_fieldt_random() -> Bigint;

    fn tinysnark_fieldt_mul(a: *const Bigint, b: *const Bigint) -> Bigint;
    fn tinysnark_fieldt_add(a: *const Bigint, b: *const Bigint) -> Bigint;
    fn tinysnark_fieldt_sub(a: *const Bigint, b: *const Bigint) -> Bigint;
    fn tinysnark_fieldt_neg(a: *const Bigint) -> Bigint;
    fn tinysnark_fieldt_inverse(a: *const Bigint) -> Bigint;

    fn tinysnark_fieldt_from(s: *const c_char) -> Bigint;
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct FieldT(Bigint);

impl Encodable for FieldT {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("FieldT", 4, |s| {
            try!(s.emit_struct_field("n0", 0, |s| {
                s.emit_u64(self.0[0])
            }));
            try!(s.emit_struct_field("n1", 0, |s| {
                s.emit_u64(self.0[1])
            }));
            try!(s.emit_struct_field("n2", 0, |s| {
                s.emit_u64(self.0[2])
            }));
            try!(s.emit_struct_field("n3", 0, |s| {
                s.emit_u64(self.0[3])
            }));
            Ok(())
        })
    }
}

impl Decodable for FieldT {
    fn decode<D: Decoder>(d: &mut D) -> Result<FieldT, D::Error> {
        initialize();

        d.read_struct("FieldT", 4, |d| {
            let n0 = try!(d.read_struct_field("n0", 0, |d| { d.read_u64() }));
            let n1 = try!(d.read_struct_field("n1", 1, |d| { d.read_u64() }));
            let n2 = try!(d.read_struct_field("n1", 2, |d| { d.read_u64() }));
            let n3 = try!(d.read_struct_field("n1", 3, |d| { d.read_u64() }));
            Ok(FieldT([n0, n1, n2, n3]))
        })
    }
}

impl FieldT {
    pub fn zero() -> Self {
        initialize();

        FieldT(unsafe { tinysnark_fieldt_zero() })
    }

    pub fn one() -> Self {
        initialize();

        FieldT(unsafe { tinysnark_fieldt_one() })
    }

    pub fn random() -> Self {
        initialize();

        FieldT(unsafe { tinysnark_fieldt_random() })
    }

    pub fn inverse(&self) -> Self {
        FieldT(unsafe { tinysnark_fieldt_inverse(&self.0) })
    }

    pub fn from_str<T: fmt::Display>(s: T) -> Option<Self> {
        let s = format!("{}", s);
        for c in s.chars() {
            if c != '0' &&
               c != '1' &&
               c != '2' &&
               c != '3' &&
               c != '4' &&
               c != '5' &&
               c != '6' &&
               c != '7' &&
               c != '8' &&
               c != '9' {
                return None;
            }
        }

        let s = CString::new(s).unwrap();
        Some(FieldT(unsafe { tinysnark_fieldt_from(s.as_ptr()) }))
    }
}

impl<'a, 'b> Mul<&'a FieldT> for &'b FieldT {
    type Output = FieldT;

    fn mul(self, other: &FieldT) -> FieldT {
        FieldT(unsafe { tinysnark_fieldt_mul(&self.0, &other.0) })
    }
}

impl<'a, 'b> Add<&'a FieldT> for &'b FieldT {
    type Output = FieldT;

    fn add(self, other: &FieldT) -> FieldT {
        FieldT(unsafe { tinysnark_fieldt_add(&self.0, &other.0) })
    }
}

impl<'a, 'b> Sub<&'a FieldT> for &'b FieldT {
    type Output = FieldT;

    fn sub(self, other: &FieldT) -> FieldT {
        FieldT(unsafe { tinysnark_fieldt_sub(&self.0, &other.0) })
    }
}

impl<'a> Neg for &'a FieldT {
    type Output = FieldT;

    fn neg(self) -> FieldT {
        FieldT(unsafe { tinysnark_fieldt_neg(&self.0) })
    }
}

impl Neg for FieldT {
    type Output = FieldT;

    fn neg(self) -> FieldT {
        -(&self)
    }
}

macro_rules! forward_val_val_binop {
    (impl($($t:ident: $p:ident),*) $imp:ident for $res:ty, $method:ident) => {
        impl<$($t: $p),*> $imp<$res> for $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: $res) -> $res {
                $imp::$method(&self, &other)
            }
        }
    }
}

macro_rules! forward_ref_val_binop {
    (impl($($t:ident: $p:ident),*) $imp:ident for $res:ty, $method:ident) => {
        impl<'a, $($t: $p),*> $imp<$res> for &'a $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: $res) -> $res {
                $imp::$method(self, &other)
            }
        }
    }
}

macro_rules! forward_val_ref_binop {
    (impl($($t:ident: $p:ident),*) $imp:ident for $res:ty, $method:ident) => {
        impl<'a, $($t: $p),*> $imp<&'a $res> for $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: &$res) -> $res {
                $imp::$method(&self, other)
            }
        }
    }
}

macro_rules! forward_all_binop_to_ref_ref {
    (impl($($t:ident: $p:ident),*) $imp:ident for $res:ty, $method:ident) => {
        forward_val_val_binop!(impl($($t: $p),*) $imp for $res, $method);
        forward_ref_val_binop!(impl($($t: $p),*) $imp for $res, $method);
        forward_val_ref_binop!(impl($($t: $p),*) $imp for $res, $method);
    };
}

forward_all_binop_to_ref_ref!(impl() Add for FieldT, add);
forward_all_binop_to_ref_ref!(impl() Sub for FieldT, sub);
forward_all_binop_to_ref_ref!(impl() Mul for FieldT, mul);
