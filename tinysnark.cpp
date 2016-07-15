#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"

using namespace libsnark;
using namespace std;

typedef Fr<default_r1cs_ppzksnark_pp> FieldT;

extern "C" void tinysnark_init() {
    default_r1cs_ppzksnark_pp::init_public_params();
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
