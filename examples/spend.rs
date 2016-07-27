extern crate tinysnark;
extern crate sha2;
extern crate rand;

use sha2::digest::Digest;
use sha2::sha2::Sha256;
use rand::{Rng,thread_rng};
use std::io::Read;
use std::fs::File;

use tinysnark::*;

fn get_path(at: usize, tree: &[Vec<u8>]) {
    unimplemented!()
}

fn random_digest() -> Vec<u8> {
    let mut rng = thread_rng();

    let mut a = vec![0; 32];
    rng.fill_bytes(&mut a);

    a
}

fn sha256<'a, I: IntoIterator<Item=&'a u8>>(i: I) -> Vec<u8> {
    let mut h = Sha256::new();

    for b in i.into_iter() {
        h.input(&[*b]);
    }

    let mut a = [0; 32];
    h.result(&mut a);

    a.to_vec()
}

fn main() {
    let sk = random_digest();
    let nf = random_digest();

    let cm = sha256(sk.iter().chain(nf.iter()));

    let addr = random_digest();
    let mac = sha256(addr.iter().chain(sk.iter()));

    // Merkle tree:

    let mut tree = vec![vec![0; 32]; 32];

    tree[16] = cm;
    for i in 17..32 {
        tree[i] = random_digest();
    }
    for i in (1..16).rev() {
        tree[i] = sha256(tree[i*2].iter().chain(tree[i*2+1].iter()));
    }

    // Witness the first element
    let mut auth_path = vec![];
    auth_path.push(tree[17].clone());
    auth_path.push(tree[9].clone());
    auth_path.push(tree[5].clone());
    auth_path.push(tree[3].clone());
    //auth_path = auth_path.iter().rev().collect();
    
    // positions
    let mut positions = vec![false, false, false, false];

    let proof = genproof(&sk, &nf, &addr, &auth_path, &positions);

    // load verifying key
    let mut vkf = File::open("zoe.vk").unwrap();
    let mut vk = vec![0; 2000];

    let r = vkf.read_to_end(&mut vk).unwrap();

    // run verifier

    drop(vkf);

    let mut a = vec![];
    a.extend(&nf);
    a.extend(&addr);
    a.extend(&tree[1]);
    a.extend(&mac);

    assert!(snark_verify(&vk[0..r], &proof[..], &a));
}
