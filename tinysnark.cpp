#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"
#include "sodium.h"

using namespace libsnark;
using namespace std;

const size_t SNARK_SIZE = 584;

typedef Fr<alt_bn128_pp> FieldT;

extern "C" void tinysnark_init() {
    assert(sodium_init() != -1);
    alt_bn128_pp::init_public_params();
}

extern "C" FieldT tinysnark_fieldt_zero() {
    return FieldT::zero();
}

extern "C" FieldT tinysnark_fieldt_one() {
    return FieldT::one();
}

extern "C" FieldT tinysnark_fieldt_random() {
    return FieldT::random_element();
}

extern "C" FieldT tinysnark_fieldt_mul(const FieldT *a, const FieldT *b) {
    return *a * *b;
}

extern "C" FieldT tinysnark_fieldt_add(const FieldT *a, const FieldT *b) {
    return *a + *b;
}

extern "C" FieldT tinysnark_fieldt_sub(const FieldT *a, const FieldT *b) {
    return *a - *b;
}

extern "C" FieldT tinysnark_fieldt_neg(const FieldT *a) {
    return -(*a);
}

extern "C" FieldT tinysnark_fieldt_inverse(const FieldT *a) {
    return a->inverse();
}

extern "C" FieldT tinysnark_fieldt_from(const char *a) {
    return FieldT(a);
}

/**
Dummy Circuit
**/

uint64_t convertVectorToInt(const std::vector<bool>& v) {
    if (v.size() > 64) {
        throw std::length_error ("boolean vector can't be larger than 64 bits");
    }

    uint64_t result = 0;
    for (size_t i=0; i<v.size();i++) {
        if (v.at(i)) {
            result |= (uint64_t)1 << ((v.size() - 1) - i);
        }
    }

    return result;
}

class MerklePath {
public:
    std::vector<std::vector<bool>> authentication_path;
    std::vector<bool> index;

    MerklePath() { }

    MerklePath(std::vector<std::vector<bool>> authentication_path, std::vector<bool> index)
    : authentication_path(authentication_path), index(index) { }
};

template<typename ppT, size_t TREEDEPTH>
class MiniZerocashCircuit {
public:
    protoboard<Fr<ppT>> pb;
    pb_variable_array<Fr<ppT>> packed_inputs;
    pb_variable_array<Fr<ppT>> unpacked_inputs;
    std::shared_ptr<multipacking_gadget<Fr<ppT>>> unpacker;
    pb_variable<Fr<ppT>> ZERO;

    std::shared_ptr<digest_variable<Fr<ppT>>> nullifier;
    std::shared_ptr<digest_variable<Fr<ppT>>> addr;
    std::shared_ptr<digest_variable<Fr<ppT>>> anchor;
    std::shared_ptr<digest_variable<Fr<ppT>>> mac;

    pb_variable_array<Fr<ppT>> sk;
    std::shared_ptr<digest_variable<Fr<ppT>>> cm;

    std::shared_ptr<sha256_compression_function_gadget<Fr<ppT>>> mac_hash;
    std::shared_ptr<sha256_compression_function_gadget<Fr<ppT>>> cm_hash;

    pb_variable_array<Fr<ppT>> positions;
    std::shared_ptr<merkle_authentication_path_variable<Fr<ppT>, sha256_two_to_one_hash_gadget<Fr<ppT>>>> authvars;
    std::shared_ptr<merkle_tree_check_read_gadget<Fr<ppT>, sha256_two_to_one_hash_gadget<Fr<ppT>>>> auth;

    MiniZerocashCircuit() {
        packed_inputs.allocate(pb, 4 + 1);
        pb.set_input_sizes(4 + 1);

        ZERO.allocate(pb);

        nullifier.reset(new digest_variable<Fr<ppT>>(pb, 256, "nullifier"));
        addr.reset(new digest_variable<Fr<ppT>>(pb, 256, "addr"));
        anchor.reset(new digest_variable<Fr<ppT>>(pb, 256, "anchor"));
        mac.reset(new digest_variable<Fr<ppT>>(pb, 256, "mac"));

        unpacked_inputs.insert(unpacked_inputs.end(), nullifier->bits.begin(), nullifier->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), addr->bits.begin(), addr->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), anchor->bits.begin(), anchor->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), mac->bits.begin(), mac->bits.end());

        unpacker.reset(new multipacking_gadget<Fr<ppT>>(
            pb,
            unpacked_inputs,
            packed_inputs,
            Fr<ppT>::capacity(),
            "unpacker"
        ));

        // AUTHENTICATION
        sk.allocate(pb, 256);

        auto IV = SHA256_default_IV(pb);

        // Note commitment
        pb_variable_array<Fr<ppT>> cm_hash_contents;
        cm_hash_contents.insert(cm_hash_contents.begin(), sk.begin(), sk.end());
        cm_hash_contents.insert(cm_hash_contents.begin(), nullifier->bits.begin(), nullifier->bits.end());

        cm.reset(new digest_variable<Fr<ppT>>(pb, 256, "cm"));
        cm_hash.reset(new sha256_compression_function_gadget<Fr<ppT>>(pb,
                                                                      IV,
                                                                      cm_hash_contents,
                                                                      *cm,
                                                                      "cm_hash"));

        // MAC
        pb_variable_array<Fr<ppT>> mac_hash_contents;
        mac_hash_contents.insert(mac_hash_contents.begin(), addr->bits.begin(), addr->bits.end());
        mac_hash_contents.insert(mac_hash_contents.begin(), sk.begin(), sk.end());

        mac_hash.reset(new sha256_compression_function_gadget<Fr<ppT>>(pb,
                                                                      IV,
                                                                      mac_hash_contents,
                                                                      *mac,
                                                                      "mac_hash"));

        // merkle tree
        positions.allocate(pb, TREEDEPTH);
        authvars.reset(new merkle_authentication_path_variable<Fr<ppT>, sha256_two_to_one_hash_gadget<Fr<ppT>>>(
            pb, TREEDEPTH, "auth"
        ));
        auth.reset(new merkle_tree_check_read_gadget<Fr<ppT>, sha256_two_to_one_hash_gadget<Fr<ppT>>>(
            pb,
            TREEDEPTH,
            positions,
            *cm,
            *anchor,
            *authvars,
            ONE,
            ""
        ));

        // constraints
        unpacker->generate_r1cs_constraints(false);
        generate_r1cs_equals_const_constraint<Fr<ppT>>(pb, ZERO, Fr<ppT>::zero(), "ZERO");

        for (size_t i = 0; i < 256; i++) {
            generate_boolean_r1cs_constraint<Fr<ppT>>(pb, sk[i]);
        }

        cm_hash->generate_r1cs_constraints();
        mac_hash->generate_r1cs_constraints();

        for (size_t i = 0; i < TREEDEPTH; i++) {
            generate_boolean_r1cs_constraint<Fr<ppT>>(
                pb,
                positions[i],
                "boolean_positions"
            );
        }

        authvars->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
    }

    r1cs_ppzksnark_keypair<ppT> keypair() {
        return r1cs_ppzksnark_generator<ppT>(pb.constraint_system);
    }

    r1cs_ppzksnark_proof<ppT> prove(const std::vector<unsigned char> sk_bytes,
                                    const std::vector<unsigned char> nullifier_bytes,
                                    const std::vector<unsigned char> addr_bytes,
                                    const MerklePath &path,
                                    const r1cs_ppzksnark_proving_key<ppT> &pk) {
        assert(sk_bytes.size() == 32);
        assert(nullifier_bytes.size() == 32);
        assert(addr_bytes.size() == 32);
        
        // sk
        {
            bool bits[256];
            for (size_t i = 0; i < 32; i++) {
                for (size_t j = 0; j < 8; j++) {
                    bits[(i*8)+j] = (sk_bytes[i] >> (7-j)) & 1;
                }
            }

            for (size_t i = 0; i < 256; i++) {
                pb.val(sk[i]) = bits[i] ? Fr<ppT>::one() : Fr<ppT>::zero();
            }
        }

        // nullifier
        {
            bool bits[256];
            for (size_t i = 0; i < 32; i++) {
                for (size_t j = 0; j < 8; j++) {
                    bits[(i*8)+j] = (nullifier_bytes[i] >> (7-j)) & 1;
                }
            }

            for (size_t i = 0; i < 256; i++) {
                pb.val(nullifier->bits[i]) = bits[i] ? Fr<ppT>::one() : Fr<ppT>::zero();
            }
        }

        // addr
        {
            bool bits[256];
            for (size_t i = 0; i < 32; i++) {
                for (size_t j = 0; j < 8; j++) {
                    bits[(i*8)+j] = (addr_bytes[i] >> (7-j)) & 1;
                }
            }

            for (size_t i = 0; i < 256; i++) {
                pb.val(addr->bits[i]) = bits[i] ? Fr<ppT>::one() : Fr<ppT>::zero();
            }
        }

        cm_hash->generate_r1cs_witness();
        mac_hash->generate_r1cs_witness();

        // merkle tree auth
        {
            size_t path_index = convertVectorToInt(path.index);
            positions.fill_with_bits_of_ulong(this->pb, path_index);

            authvars->generate_r1cs_witness(path_index, path.authentication_path);
            auth->generate_r1cs_witness();
        }

        assert(pb.is_satisfied());

        r1cs_ppzksnark_primary_input<ppT> primary_input = pb.primary_input();
        r1cs_ppzksnark_auxiliary_input<ppT> aux_input = pb.auxiliary_input();

        pb.constraint_system.swap_AB_if_beneficial();

        return r1cs_ppzksnark_prover<ppT>(pk, primary_input, aux_input, pb.constraint_system);
    }

    static vector<Fr<ppT>> witness_map(
        std::vector<unsigned char> nf_bytes,
        std::vector<unsigned char> addr_bytes,
        std::vector<unsigned char> anchor_bytes,
        std::vector<unsigned char> mac_bytes
    ) {
        assert(nf_bytes.size() == 32);
        assert(addr_bytes.size() == 32);
        assert(anchor_bytes.size() == 32);
        assert(mac_bytes.size() == 32);

        vector<bool> bits(256 * 4);
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((256 * 0) + (i*8)+j) = (nf_bytes[i] >> (7-j)) & 1;
            }
        }
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((256 * 1) + (i*8)+j) = (addr_bytes[i] >> (7-j)) & 1;
            }
        }
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((256 * 2) + (i*8)+j) = (anchor_bytes[i] >> (7-j)) & 1;
            }
        }
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((256 * 3) + (i*8)+j) = (mac_bytes[i] >> (7-j)) & 1;
            }
        }

        return pack_bit_vector_into_field_element_vector<Fr<ppT>>(bits);
    }
};

extern "C" bool tinysnark_test() {
    MiniZerocashCircuit<alt_bn128_pp, 4> c;
    auto kp = c.keypair();

    /*
    auto proof = c.prove(preimage, kp.pk);
    auto primary = MiniZerocashCircuit<alt_bn128_pp>::witness_map(image);

    return r1cs_ppzksnark_verifier_strong_IC<alt_bn128_pp>(kp.vk, primary, proof);
    */
    return true;
}


/*
template<typename ppT>
class Proof {
public:
    unsigned char proofdata[SNARK_SIZE];

    Proof(const r1cs_ppzksnark_proof<ppT> &proof) {
        std::stringstream ss;
        ss << proof;
        std::string serialized_proof = ss.str();
        assert(serialized_proof.size() == SNARK_SIZE);
        memcpy(&proofdata[0], &serialized_proof[0], SNARK_SIZE);
    }
};

extern "C" Proof<alt_bn128_pp> get_preimage_proof(unsigned char preimage[32], unsigned char *pkdata, uint32_t s)
{
    MiniZerocashCircuit<alt_bn128_pp> c;

    // load keypair from caller
    r1cs_ppzksnark_proving_key<alt_bn128_pp> pk;
    std::stringstream ss;
    std::string pk_str(pkdata, pkdata+s);
    ss.str(pk_str);
    ss >> pk;

    return c.prove(preimage, pk);
}
*/