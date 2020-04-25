#ifndef PS_SRC_PROTOBUF_ENCODING_H_
#define PS_SRC_PROTOBUF_ENCODING_H_

#include "ps.pb.h"
#include <mcl/bls12_381.hpp>

using namespace mcl::bls12;

std::shared_ptr<PSCredential>
protobuf_encode_ps_credential(const G1& sig1, const G1& sig2);

void
protobuf_decode_ps_credential(const PSCredential& credential, G1& sig1, G1& sig2);

std::shared_ptr<PSPubKey>
protobuf_encode_ps_pk(const G1& g, const G2& gg, const G2& XX, const std::vector<G1>& Yi, const std::vector<G2>& YYi);

void
protobuf_decode_ps_pk(const PSPubKey& pk, G1& g, G2& gg, G2& XX, std::vector<G1>& Yi, std::vector<G2>& YYi);

std::shared_ptr<PSCredRequest>
protobuf_encode_sign_request(const G1& A, const Fr& c, const std::vector<Fr>& rs, const std::vector<std::string>& plaintext_attributes);

void
protobuf_decode_sign_request(const PSCredRequest& request, G1& A, Fr& c, std::vector<Fr>& rs, std::vector<std::string>& plaintext_attributes);

#endif // PS_SRC_PROTOBUF_ENCODING_H_