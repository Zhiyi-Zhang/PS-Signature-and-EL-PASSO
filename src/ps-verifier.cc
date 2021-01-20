#include "ps-verifier.h"

#include <chrono>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

PSVerifier::PSVerifier(const PSPubKey& pk)
    : m_pk(pk)
{
}

bool
PSVerifier::verify(const PSCredential& sig, const std::vector<std::string>& all_attributes) const
{
  if (sig.sig1.isZero()) {
    return false;
  }

  Fr _attribute_hash;
  G2 _yy_hash_sum = m_pk.XX;
  int counter = 0;
  G2 _yyi_hash_product;
  for (const auto& attribute : all_attributes) {
    _attribute_hash.setHashOf(attribute);
    G2::mul(_yyi_hash_product, m_pk.YYi[counter], _attribute_hash);
    G2::add(_yy_hash_sum, _yy_hash_sum, _yyi_hash_product);
    counter++;
  }

  GT _lhs, _rhs;
  pairing(_lhs, sig.sig1, _yy_hash_sum);
  pairing(_rhs, sig.sig2, m_pk.gg);
  return _lhs == _rhs;
}

bool
PSVerifier::el_passo_verify_id(const IdProof& proof,
                               const std::string& associated_data,
                               const std::string& service_name,
                               const G1& authority_pk, const G1& g, const G1& h) const
{
  /** NIZK Verify:
   * Public Value:
   * * k = XX * PI{ YY_j^attribute_j } * gg^t
   * * phi = hash(domain)^s
   * * E1 = g^epsilon
   * * E2 = y^epsilon * h^gamma
   *
   * Public Random Value:
   * * V_k = XX * PI{ YYj^random1_j } * gg^random_2
   *       = k^c * XX^(1-c) * PI{ YYj^r1_j } * gg^r2
   * * V_phi = hash(domain)^random1_s
   *         = phi^c * hash(domain)^r1_s
   * * V_E1 = g^random_3
   *        = E1^c * g^r3
   * * V_E2 = y^random_3 * h^random1_gamma
   *        = E2^c * y^r3 * h^r1_gamma
   *
   * c: to be compared
   * c = hash(k || phi || E1 || E2 || V_k || V_phi || V_E1 || V_E2 || associated_data )
   *
   * Rs:
   * * r1_j: random1_j - attribute_j * c
   * * r2: random2 - t * c
   * * r3: random3 - epsilon * c
   */
  if (!proof.E1.has_value() || !proof.E2.has_value()) {
    return false;
  }
  // V_k = k^c * XX^(1-c) * PI{ YYj^r1_j } * gg^r2
  G2 _V_k;
  G2::mul(_V_k, proof.k, proof.c);
  int counter = 0;
  G2 _base_r;
  for (size_t i = 0; i < proof.attributes.size(); i++) {
    if (proof.attributes[i] == "") {
      G2::mul(_base_r, m_pk.YYi[i], proof.rs[counter]);
      counter++;
      G2::add(_V_k, _V_k, _base_r);
    }
  }
  G2::mul(_base_r, m_pk.gg, proof.rs[proof.rs.size() - 2]);
  G2::add(_V_k, _V_k, _base_r);
  Fr _1_c = Fr::one();
  Fr::sub(_1_c, _1_c, proof.c);
  G2::mul(_base_r, m_pk.XX, _1_c);
  G2::add(_V_k, _V_k, _base_r);

  // V_phi = phi^c * hash(domain)^r1_s
  G1 _V_phi, _V_E1, _V_E2;
  G1::mul(_V_phi, proof.phi, proof.c);
  G1 _temp;
  hashAndMapToG1(_temp, service_name);
  G1::mul(_temp, _temp, proof.rs[0]);
  G1::add(_V_phi, _V_phi, _temp);

  // V_E1 = E1^c * g^r3
  G1::mul(_V_E1, proof.E1.value(), proof.c);
  G1::mul(_temp, g, proof.rs[proof.rs.size() - 1]);
  G1::add(_V_E1, _V_E1, _temp);

  // V_E2 = E2^c * y^r3 * h^r1_gamma
  G1::mul(_V_E2, proof.E2.value(), proof.c);
  G1::mul(_temp, authority_pk, proof.rs[proof.rs.size() - 1]);
  G1::add(_V_E2, _V_E2, _temp);
  G1::mul(_temp, h, proof.rs[1]);
  G1::add(_V_E2, _V_E2, _temp);

  // Calculate c = hash(k || phi || E1 || E2 || V_k || V_phi || V_E1 || V_E2 || associated_data )
  Fr _local_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(proof.k.serializeToHexStr());
  digest_engine.update(proof.phi.serializeToHexStr());
  digest_engine.update(proof.E1.value().serializeToHexStr());
  digest_engine.update(proof.E2.value().serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  digest_engine.update(_V_E1.serializeToHexStr());
  digest_engine.update(_V_E2.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _local_c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E1: " << _V_E1.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E2: " << _V_E2.serializeToHexStr() << std::endl;

  if (proof.c != _local_c) {
    return false;
  }

  // signature verification, e(sigma’_1, k) ?= e(sigma’_2, gg)
  G2 _final_k = prepare_hybrid_verification(proof.k, proof.attributes);
  GT lhs, rhs;
  pairing(lhs, proof.sig1, _final_k);
  pairing(rhs, proof.sig2, m_pk.gg);
  return lhs == rhs;
}

bool
PSVerifier::el_passo_verify_id_without_id_retrieval(const IdProof& proof,
                                                    const std::string& associated_data,
                                                    const std::string& service_name) const
{
  /** NIZK Verify:
   * Public Value:
   * * k = XX * PI{ YY_j^attribute_j } * gg^t
   * * phi = hash(domain)^s
   *
   * Public Random Value:
   * * V_k = XX * PI{ YYj^random1_j } * gg^random_2
   *       = k^c * XX^(1-c) * PI{ YYj^r1_j } * gg^r2
   * * V_phi = hash(domain)^random1_s
   *         = phi^c * hash(domain)^r1_s
   *
   * c: to be compared
   * c = hash(k || phi || V_k || V_phi || associated_data )
   *
   * Rs:
   * * r1_j: random1_j - attribute_j * c
   * * r2: random2 - t * c
   */
  // V_k = k^c * XX^(1-c) * PI{ YYj^r1_j } * gg^r2
  G2 _V_k;
  G2::mul(_V_k, proof.k, proof.c);
  int counter = 0;
  G2 _base_r;
  for (size_t i = 0; i < proof.attributes.size(); i++) {
    if (proof.attributes[i] == "") {
      G2::mul(_base_r, m_pk.YYi[i], proof.rs[counter]);
      counter++;
      G2::add(_V_k, _V_k, _base_r);
    }
  }
  G2::mul(_base_r, m_pk.gg, proof.rs[proof.rs.size() - 1]);
  G2::add(_V_k, _V_k, _base_r);
  Fr _1_c = Fr::one();
  Fr::sub(_1_c, _1_c, proof.c);
  G2::mul(_base_r, m_pk.XX, _1_c);
  G2::add(_V_k, _V_k, _base_r);

  // V_phi = phi^c * hash(domain)^r1_s
  G1 _V_phi;
  G1::mul(_V_phi, proof.phi, proof.c);
  G1 _temp;
  hashAndMapToG1(_temp, service_name);
  G1::mul(_temp, _temp, proof.rs[0]);
  G1::add(_V_phi, _V_phi, _temp);

  // Calculate c = hash(k || phi || V_k || V_phi || associated_data )
  Fr _local_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(proof.k.serializeToHexStr());
  digest_engine.update(proof.phi.serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _local_c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;

  if (proof.c != _local_c) {
    return false;
  }

  // signature verification, e(sigma’_1, k) ?= e(sigma’_2, gg)
  G2 _final_k = prepare_hybrid_verification(proof.k, proof.attributes);
  GT lhs, rhs;
  pairing(lhs, proof.sig1, _final_k);
  pairing(rhs, proof.sig2, m_pk.gg);
  return lhs == rhs;
}

G2
PSVerifier::prepare_hybrid_verification(const G2& k, const std::vector<std::string>& attributes) const
{
  G2 _final_k = k;
  G2 _temp_yyi_hash;
  Fr _temp_hash;
  for (size_t i = 0; i < attributes.size(); i++) {
    if (attributes[i] == "") {
      continue;
    }
    _temp_hash.setHashOf(attributes[i]);
    G2::mul(_temp_yyi_hash, m_pk.YYi[i], _temp_hash);
    G2::add(_final_k, _final_k, _temp_yyi_hash);
  }
  return _final_k;
}