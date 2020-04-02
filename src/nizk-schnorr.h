#ifndef PS_SRC_NIZK_SCHNORR_H_
#define PS_SRC_NIZK_SCHNORR_H_

#include <string>
#include <mcl/bls12_381.hpp>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

void
nizk_schnorr_prove(const G1& g, const Fp& a,
                   const std::string& associated_data,
                   G1& A, G1& V, Fp& r);

bool
nizk_schnorr_verify(const G1& g, const G1& A, const G1& V,
                    const Fp& r, const std::string& associated_data);

#endif // PS_SRC_NIZK_SCHNORR_H_