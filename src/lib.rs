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
    fn tinysnark_verify(
        vk: *const libc::c_uchar,
        vk_size: libc::uint32_t,
        proof: *const libc::c_uchar,
        proof_size: libc::uint32_t,
        primary: *const libc::c_uchar,
        primary_size: libc::uint32_t
    ) -> bool;

    fn generate_proof(
        sk: *const libc::c_uchar,
        nf: *const libc::c_uchar,
        addr: *const libc::c_uchar,
        path: *const libc::c_uchar,
        positions: *const bool
    ) -> [u8; 584];
}

pub fn genproof(sk: &[u8], nf: &[u8], addr: &[u8], path: &Vec<Vec<u8>>, positions: &[bool]) -> [u8; 584] {
    initialize();

    assert_eq!(path.len(), 4);
    let path: Vec<u8> = path.iter().flat_map(|a| a.iter()).map(|a| *a).collect();
    assert_eq!(path.len(), 4 * 32);

    assert_eq!(sk.len(), 32);
    assert_eq!(nf.len(), 32);
    assert_eq!(addr.len(), 32);
    assert_eq!(positions.len(), 4);

    unsafe { generate_proof(&sk[0], &nf[0], &addr[0], &path[0], &positions[0]) }
}

pub fn snark_verify(
    vk: &[u8],
    proof: &[u8],
    primary: &[u8]
) -> bool {
    initialize();

    unsafe { tinysnark_verify(&vk[0], vk.len() as u32, &proof[0], proof.len() as u32, &primary[0], primary.len() as u32) }
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
