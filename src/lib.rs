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
