use std::sync::Mutex;

extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate rustc_serialize;

lazy_static! {
    static ref INIT_LOCK: Mutex<bool> = Mutex::new(false);
}

mod arith;

extern "C" {
    fn tinysnark_init();
    fn tinysnark_test() -> bool;
}

pub fn initialize() {
    let mut l = INIT_LOCK.lock().unwrap();

    if !*l {
        unsafe { tinysnark_init(); }
        *l = true;
    }
}

#[test]
fn lol() {
    use arith::*;

    let b = FieldT::random();
}

#[test]
fn test_from() {
    use arith::*;

    let a = FieldT::one() + FieldT::one() + FieldT::one() + FieldT::one();
    let b = FieldT::from_str("4").unwrap();

    assert!(a == b);
    assert!(a + FieldT::one() != b);
}

#[test]
fn test_dummy_circuit() {
    initialize();

    assert!(unsafe { tinysnark_test() });
}
