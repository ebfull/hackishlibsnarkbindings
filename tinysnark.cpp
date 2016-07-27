#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"
#include "sodium.h"

using namespace libsnark;
using namespace std;

// PADDING
// 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0

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

template<typename FieldT>
pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

    for (size_t i = 0; i < bits.size(); i++) {
        acc.emplace_back(bits[i] ? ONE : ZERO);
    }

    return acc;
}

template<typename FieldT>
class sha256_full_two_to_one_gadget : public gadget<FieldT> {
public:
    typedef bit_vector hash_value_type;
    typedef merkle_authentication_path merkle_authentication_path_type;

    std::shared_ptr<sha256_compression_function_gadget<FieldT> > f1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT> > f2;
    pb_variable<FieldT> ZERO;

    sha256_full_two_to_one_gadget(protoboard<FieldT> &pb,
                                 const size_t block_length,
                                 const block_variable<FieldT> &input_block,
                                 const digest_variable<FieldT> &output,
                                 const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix)
    {
        ZERO.allocate(pb);

        auto IV = SHA256_default_IV(pb);

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

        f1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            input_block.bits,
            *intermediate_hash,
        ""));

        // second block
        pb_variable_array<FieldT> length_padding =
            from_bits({
                // padding
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,0,
                0,0,0,0,0,0,0,0
            }, ZERO);

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        f2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            length_padding,
            output,
        ""));
    }

    sha256_full_two_to_one_gadget(protoboard<FieldT> &pb,
                                  const digest_variable<FieldT> &left,
                                  const digest_variable<FieldT> &right,
                                  const digest_variable<FieldT> &output,
                                  const std::string &annotation_prefix)
    : sha256_full_two_to_one_gadget(pb,
                                    512,
                                    block_variable<FieldT>(pb, {left.bits, right.bits}, ""),
                                    output,
                                    annotation_prefix)
    {

    }

    void generate_r1cs_constraints(const bool ensure_output_bitness=true)
    {
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");
        f1->generate_r1cs_constraints();
        f2->generate_r1cs_constraints();
    }
    void generate_r1cs_witness() {
        f1->generate_r1cs_witness();
        f2->generate_r1cs_witness();
    }

    static size_t get_block_len()
    {
        return 512;
    }

    static size_t get_digest_len()
    {
        return 256;
    }
};

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
    MerklePath(size_t i) {
        for (size_t j = 0; j < i; j++) {
            index.push_back(0);

            std::vector<bool> v(256, 0);
            assert(v.size() == 256);

            authentication_path.push_back(v);
        }
    }

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

    std::shared_ptr<digest_variable<Fr<ppT>>> sk;
    std::shared_ptr<digest_variable<Fr<ppT>>> cm;

    std::shared_ptr<sha256_full_two_to_one_gadget<Fr<ppT>>> mac_hash;
    std::shared_ptr<sha256_full_two_to_one_gadget<Fr<ppT>>> cm_hash;

    pb_variable_array<Fr<ppT>> positions;
    std::shared_ptr<merkle_authentication_path_variable<Fr<ppT>, sha256_full_two_to_one_gadget<Fr<ppT>>>> authvars;
    std::shared_ptr<merkle_tree_check_read_gadget<Fr<ppT>, sha256_full_two_to_one_gadget<Fr<ppT>>>> auth;

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
        sk.reset(new digest_variable<Fr<ppT>>(pb, 256, "sk"));

        // Note commitment
        cm.reset(new digest_variable<Fr<ppT>>(pb, 256, "cm"));
        cm_hash.reset(new sha256_full_two_to_one_gadget<Fr<ppT>>(
            pb, *sk, *nullifier, *cm, "cm_hash"
        ));

        // MAC
        mac_hash.reset(new sha256_full_two_to_one_gadget<Fr<ppT>>(
            pb, *addr, *sk, *mac, "mac_hash"
        ));

        // merkle tree
        positions.allocate(pb, TREEDEPTH);
        authvars.reset(new merkle_authentication_path_variable<Fr<ppT>, sha256_full_two_to_one_gadget<Fr<ppT>>>(
            pb, TREEDEPTH, "auth"
        ));
        auth.reset(new merkle_tree_check_read_gadget<Fr<ppT>, sha256_full_two_to_one_gadget<Fr<ppT>>>(
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

        addr->generate_r1cs_constraints();
        sk->generate_r1cs_constraints();
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
                pb.val(sk->bits[i]) = bits[i] ? Fr<ppT>::one() : Fr<ppT>::zero();
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

        // unpack
        unpacker->generate_r1cs_witness_from_bits();

        assert(pb.is_satisfied());

        r1cs_ppzksnark_primary_input<ppT> primary_input = pb.primary_input();
        r1cs_ppzksnark_auxiliary_input<ppT> aux_input = pb.auxiliary_input();

        pb.constraint_system.swap_AB_if_beneficial();

        return r1cs_ppzksnark_prover<ppT>(pk, primary_input, aux_input, pb.constraint_system);
    }
};

extern "C" bool tinysnark_verify(
    unsigned char *vk_bytes,
    uint32_t vk_size,
    unsigned char *proof_bytes,
    uint32_t proof_size,
    unsigned char *primary_input_bytes,
    uint32_t primary_input_len

) {
    try {
    r1cs_ppzksnark_verification_key<alt_bn128_pp> vk;
    {
        std::stringstream ss;
        std::string s(vk_bytes, vk_bytes+vk_size);
        ss.str(s);
        ss >> vk;
    }
    r1cs_ppzksnark_proof<alt_bn128_pp> proof;
    {
        std::stringstream ss;
        std::string s(proof_bytes, proof_bytes+proof_size);
        ss.str(s);
        ss >> proof;
    }
    std::vector<bool> primary_input_bits(primary_input_len * 8);
    for (size_t i = 0; i < primary_input_len; i++) {
        for (size_t j = 0; j < 8; j++) {
            primary_input_bits.at((256 * 2) + (i*8)+j) = (primary_input_bytes[i] >> (7-j)) & 1;
        }
    }

    auto primary = pack_bit_vector_into_field_element_vector<FieldT>(primary_input_bits);

    return r1cs_ppzksnark_verifier_strong_IC<alt_bn128_pp>(vk, primary, proof);
    } catch(...) {
        return false;
    }
}

extern "C" bool generate_proof(
    unsigned char *sk,
    unsigned char *nullifier,
    unsigned char *addr,
    unsigned char *path_digests,
    bool *position_bools
)
{
    std::vector<unsigned char> skv(sk, sk+32);
    std::vector<unsigned char> nfv(nullifier, nullifier+32);
    std::vector<unsigned char> addrv(addr, addr+32);

    std::vector<std::vector<bool>> digests;
    for (size_t i = 0; i < 4; i++) {
        std::vector<bool> bits(256);
        for (size_t i2 = 0; i2 < 32; i2++) {
            for (size_t j = 0; j < 8; j++) {
                bits.at((i2*8)+j) = (path_digests[i * 32 + i2] >> (7-j)) & 1;
            }
        }
        digests.push_back(bits);
    }

    std::vector<bool> positions(position_bools, position_bools+4);

    MerklePath path(digests, positions);

    MiniZerocashCircuit<alt_bn128_pp, 4> c;
    auto kp = c.keypair();

    auto proof = c.prove(skv, nfv, addrv, path, kp.pk);

    return true;
}

extern "C" bool tinysnark_test() {
    MiniZerocashCircuit<alt_bn128_pp, 4> c;
    auto kp = c.keypair();

    std::vector<unsigned char> sk = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    std::vector<unsigned char> serial = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    std::vector<unsigned char> addr = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    MerklePath path(4);

    auto proof = c.prove(sk, serial, addr, path, kp.pk);

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