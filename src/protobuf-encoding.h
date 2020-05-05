#ifndef PS_SRC_PROTOBUF_ENCODING_H_
#define PS_SRC_PROTOBUF_ENCODING_H_

#include <mcl/bls12_381.hpp>

#include "ps.pb.h"

using namespace mcl::bls12;

/**
 * PS Credential Encoding and Decoding.
 */
std::shared_ptr<PSCredential>
protobuf_encode_ps_credential(const G1& sig1, const G1& sig2);

void
protobuf_decode_ps_credential(const PSCredential& credential, G1& sig1, G1& sig2);

/**
 * PS Public Key Encoding and Decoding.
 */
std::shared_ptr<PSPubKey>
protobuf_encode_ps_pk(const G1& g, const G2& gg, const G2& XX, const std::vector<G1>& Yi, const std::vector<G2>& YYi);

void
protobuf_decode_ps_pk(const PSPubKey& pk, G1& g, G2& gg, G2& XX, std::vector<G1>& Yi, std::vector<G2>& YYi);

/**
 * PS Signature Request Encoding and Decoding.
 */
std::shared_ptr<PSCredRequest>
protobuf_encode_sign_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                             const std::vector<std::string>& attributes);

void
protobuf_decode_sign_request(const PSCredRequest& request, G1& A, Fr& c, std::vector<Fr>& rs,
                             std::vector<std::string>& attributes);

/**
 * ID Prove Encoding and Decoding.
 */
std::shared_ptr<ProveID>
protobuf_encode_prove_id(const G1& sig1, const G1& sig2, const G2& k, const G1& phi,
                         const G1& E1, const G1& E2, const Fr& c,
                         const std::vector<Fr>& rsize_t, const std::vector<std::string>& attributes);

void
protobuf_decode_prove_id(const ProveID& prove_id, G1& sig1, G1& sig2, G2& k, G1& phi,
                         G1& E1, G1& E2, Fr& c,
                         std::vector<Fr>& rsize_t, std::vector<std::string>& attributes);

#endif  // PS_SRC_PROTOBUF_ENCODING_H_