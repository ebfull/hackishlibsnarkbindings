#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
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

template<typename ppT>
class DummyCircuit {
public:
    protoboard<Fr<ppT>> pb;
    pb_variable_array<Fr<ppT>> packed_inputs;
    std::shared_ptr<multipacking_gadget<Fr<ppT>>> unpacker;
    pb_variable<FieldT> ZERO;

    std::shared_ptr<digest_variable<Fr<ppT>>> image;
    pb_variable_array<Fr<ppT>> preimage;
    std::shared_ptr<sha256_compression_function_gadget<Fr<ppT>>> hash;

    DummyCircuit() {
        packed_inputs.allocate(pb, 2);
        pb.set_input_sizes(2);

        ZERO.allocate(pb);

        image.reset(new digest_variable<Fr<ppT>>(pb, 256, "image"));

        unpacker.reset(new multipacking_gadget<Fr<ppT>>(
            pb,
            image->bits,
            packed_inputs,
            Fr<ppT>::capacity(),
            "unpacker"
        ));
        unpacker->generate_r1cs_constraints(false);

        preimage.allocate(pb, 256);

        bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

        for (size_t i = 0; i < 256; i++) {
            preimage.emplace_back(sha256_padding[i] ? ONE : ZERO);
        }

        auto IV = SHA256_default_IV(pb);
        hash.reset(new sha256_compression_function_gadget<Fr<ppT>>(pb,
                                                                  IV,
                                                                  preimage,
                                                                  *image,
                                                                  "sha256"));


        generate_r1cs_equals_const_constraint<Fr<ppT>>(pb, ZERO, Fr<ppT>::zero(), "ZERO");
        
        for (size_t i = 0; i < 256; i++) {
            generate_boolean_r1cs_constraint<Fr<ppT>>(pb, preimage[i]);
        }
        hash->generate_r1cs_constraints();
    }

    r1cs_ppzksnark_keypair<ppT> keypair() {
        return r1cs_ppzksnark_generator<ppT>(pb.constraint_system);
    }

    r1cs_ppzksnark_proof<ppT> prove(unsigned char preimage_bytes[32], const r1cs_ppzksnark_proving_key<ppT> &pk) {
        bool preimage_bits[256];

        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                preimage_bits[(i*8)+j] = (preimage_bytes[i] >> (7-j)) & 1;
            }
        }

        for (size_t i = 0; i < 256; i++) {
            pb.val(preimage[i]) = preimage_bits[i] ? Fr<ppT>::one() : Fr<ppT>::zero();
        }

        hash->generate_r1cs_witness();
        unpacker->generate_r1cs_witness_from_bits();

        assert(pb.is_satisfied());

        r1cs_ppzksnark_primary_input<ppT> primary_input = pb.primary_input();
        r1cs_ppzksnark_auxiliary_input<ppT> aux_input = pb.auxiliary_input();

        pb.constraint_system.swap_AB_if_beneficial();

        return r1cs_ppzksnark_prover<ppT>(pk, primary_input, aux_input, pb.constraint_system);
    }

    static vector<Fr<ppT>> witness_map(unsigned char image_bytes[32]) {
        vector<bool> bits(256);
        for (size_t i = 0; i < 32; i++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((i*8)+j) = (image_bytes[i] >> (7-j)) & 1;
            }
        }

        return pack_bit_vector_into_field_element_vector<Fr<ppT>>(bits);
    }
};

extern "C" bool tinysnark_test() {
    DummyCircuit<alt_bn128_pp> c;
    auto kp = c.keypair();

    unsigned char preimage[32] = {'V','e','r','s','a','c','e',',',
                                  'V','e','r','s','a','c','e',',',
                                  'V','e','r','s','a','c','e',',',
                                  'V','e','r','s','a','c','e','!'
                                 };

    unsigned char    image[32] = {0x6e, 0x30, 0xda, 0x2d, 0x26, 0x0e, 0x4d, 0x71,
                                  0x16, 0x9f, 0xea, 0x88, 0xe1, 0x04, 0x7d, 0xbb,
                                  0xfb, 0x47, 0x10, 0xea, 0x11, 0xc0, 0xed, 0x3f,
                                  0x66, 0x21, 0x35, 0x2f, 0xa8, 0x19, 0xe4, 0x75
                                 };

    auto proof = c.prove(preimage, kp.pk);
    auto primary = DummyCircuit<alt_bn128_pp>::witness_map(image);

    return r1cs_ppzksnark_verifier_strong_IC<alt_bn128_pp>(kp.vk, primary, proof);
}

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
    DummyCircuit<alt_bn128_pp> c;

    // load keypair from caller
    r1cs_ppzksnark_proving_key<alt_bn128_pp> pk;
    std::stringstream ss;
    std::string pk_str(pkdata, pkdata+s);
    ss.str(pk_str);
    ss >> pk;

    return c.prove(preimage, pk);
}
