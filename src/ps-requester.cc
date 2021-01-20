#include "ps-requester.h"

#include <chrono>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

PSRequester::PSRequester(const PSPubKey& pk)
    : m_pk(pk)
{
}

size_t
PSRequester::maxAllowedAttrNum() const
{
  return m_pk.Yi.size();
}

PSCredRequest
PSRequester::el_passo_request_id(const std::vector<std::tuple<std::string, bool>> attributes,  // string is the attribute, bool whether to hide
                                 const std::string& associated_data)
{
  /** NIZK Prove:
   * Public Value: A = g^t * PI{Yi^(attribute_i)}, will be sent
   * Public Random Value: V = g^random1 * PROD{Yi^(random2_i)}, will not be sent
   * c = hash( A || V || associated_data);, will be sent
   * r0 = random1 - t*c; r1 = random2_i - attribute_i * c, will be sent
   */
  // calcuate the max number of attributes supported
  size_t maxAllowedAttrNum = m_pk.Yi.size();
  if (attributes.size() != maxAllowedAttrNum) {
    throw std::runtime_error("attribute size does not match");
  }
  // parameters to send:
  PSCredRequest request;
  request.rs.reserve(attributes.size() + 1);
  // Prepare for A
  m_t1.setByCSPRNG();
  G1::mul(request.A, m_pk.g, m_t1);
  Fr _attribute_hash;
  G1 _Yi_hash, _Yi_randomness;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  // Parepare for randomness
  std::vector<Fr> _randomnesses;
  _randomnesses.reserve(attributes.size() + 1);
  Fr _temp_randomness;
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness);  // the randomness for g^t
  // prepare for V
  G1 _V;
  G1::mul(_V, m_pk.g, _temp_randomness);
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      // this attribute needs to be commitmented
      // calculate A
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G1::mul(_Yi_hash, m_pk.Yi[i], _attribute_hash);
      G1::add(request.A, request.A, _Yi_hash);
      // generate randomness
      _temp_randomness.setByCSPRNG();
      _randomnesses.push_back(_temp_randomness);  // the randomness for message i
      // calculate V
      G1::mul(_Yi_randomness, m_pk.Yi[i], _temp_randomness);
      G1::add(_V, _V, _Yi_randomness);
    }
  }
  // Calculate c
  cybozu::Sha256 digest_engine;
  digest_engine.update(request.A.serializeToHexStr());
  digest_engine.update(_V.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  request.c.setHashOf(_c_str);
  // std::cout << "parepare: A: " << request.A.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V: " << _V.serializeToHexStr() << std::endl;
  // std::cout << "parepare: c: " << request.c.serializeToHexStr() << std::endl;
  // Calculate rs
  Fr _r_temp;
  Fr::mul(_r_temp, m_t1, request.c);
  Fr::sub(_r_temp, _randomnesses[0], _r_temp);
  request.rs.push_back(_r_temp);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_r_temp, _attribute_hashes[i], request.c);
    Fr::sub(_r_temp, _randomnesses[i + 1], _r_temp);
    request.rs.push_back(_r_temp);
  }
  // plaintext attributes
  request.attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      request.attributes.push_back("");
    }
    else {
      request.attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  return request;
}

PSCredential
PSRequester::unblind_credential(const PSCredential& sig) const
{
  // unblinded_sig <- (sig_1, sig_2 / sig_1^t)
  PSCredential newSig;
  newSig.sig1 = sig.sig1;

  G1 _sig1_t;
  G1::mul(_sig1_t, sig.sig1, m_t1);
  G1::sub(newSig.sig2, sig.sig2, _sig1_t);

  return newSig;
}

bool
PSRequester::verify(const PSCredential& sig, const std::vector<std::string>& all_attributes) const
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

PSCredential
PSRequester::randomize_credential(const PSCredential& sig) const
{
  PSCredential newSig;
  Fr t;
  t.setByCSPRNG();
  G1::mul(newSig.sig1, sig.sig1, t);
  G1::mul(newSig.sig2, sig.sig2, t);
  return newSig;
}

IdProof  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
PSRequester::el_passo_prove_id(const PSCredential& sig,
                               const std::vector<std::tuple<std::string, bool>> attributes,
                               const std::string& associated_data,
                               const std::string& service_name,
                               const G1& authority_pk, const G1& g, const G1& h) const
{
  size_t maxAllowedAttrNum = m_pk.Yi.size();
  if (attributes.size() != maxAllowedAttrNum) {
    throw std::runtime_error("attribute size does not match");
  }

  IdProof proof;
  // new_sig = sig1^r, (sig2 + sig1^t)^r
  Fr _t, _r;
  _t.setByCSPRNG();
  _r.setByCSPRNG();
  G1::mul(proof.sig1, sig.sig1, _r);
  G1::mul(proof.sig2, sig.sig1, _t);
  G1::add(proof.sig2, proof.sig2, sig.sig2);
  G1::mul(proof.sig2, proof.sig2, _r);

  // El Gamal Cipher E = g^epsilon, y^epsilon * h^gamma
  G1 _E1, _E2, _h_gamma;
  Fr _epsilon, _gamma;
  _epsilon.setByCSPRNG();
  _gamma.setHashOf(std::get<0>(attributes[1]));
  G1::mul(_E1, g, _epsilon);
  G1::mul(_E2, authority_pk, _epsilon);
  G1::mul(_h_gamma, h, _gamma);
  G1::add(_E2, _E2, _h_gamma);

  // phi = hash(service_name)^gamma
  G1 _service_hash;
  Fr _s;
  hashAndMapToG1(_service_hash, service_name);
  _s.setHashOf(std::get<0>(attributes[0]));
  G1::mul(proof.phi, _service_hash, _s);

  // k = XX * PI{ YYj^mj } * gg^t
  proof.k = m_pk.XX;
  Fr _attribute_hash;
  G2 _yy_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G2::mul(_yy_hash, m_pk.YYi[i], _attribute_hash);
      G2::add(proof.k, proof.k, _yy_hash);
    }
  }
  G2::mul(_yy_hash, m_pk.gg, _t);
  G2::add(proof.k, proof.k, _yy_hash);

  /** NIZK Prove:
   * Public Value: will be sent
   * * k = XX * PI{ YY_j^attribute_j } * gg^t
   * * phi = hash(domain)^s
   * * E1 = g^epsilon
   * * E2 = y^epsilon * h^gamma
   *
   * Public Random Value: will not be sent
   * * V_k = XX * PI{ YYj^random1_j } * gg^random_2
   * * V_phi = hash(domain)^random1_s
   * * V_E1 = g^random_3
   * * V_E2 = y^random_3 * h^random1_gamma
   *
   * c: will be sent
   * c = hash(k || phi || E1 || E2 || V_k || V_phi || V_E1 || V_E2 || associated_data )
   *
   * Rs: will be sent
   * * random1_j - attribute_j * c
   * * random2 - t * c
   * * random3 - epsilon * c
   */
  // V_k = XX * PI{ YYj^random1_j } * gg^random_2
  G2 _V_k = m_pk.XX;
  std::vector<Fr> _randomnesses;
  Fr _temp_randomness;
  G2 _yy_randomness;
  _randomnesses.reserve(attributes.size() + 2);
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _temp_randomness.setByCSPRNG();
      _randomnesses.push_back(_temp_randomness);
      G2::mul(_yy_randomness, m_pk.YYi[i], _temp_randomness);
      G2::add(_V_k, _V_k, _yy_randomness);
    }
  }
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness);  // random2
  G2::mul(_yy_randomness, m_pk.gg, _temp_randomness);
  G2::add(_V_k, _V_k, _yy_randomness);

  // V_phi
  G1 _V_phi;
  G1::mul(_V_phi, _service_hash, _randomnesses[0]);  // random1_s

  // V_E1 = g^random_3
  G1 _V_E1;
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness);  // random 3
  G1::mul(_V_E1, g, _temp_randomness);

  // V_E2 = y^random_3 * h^random1_gamma
  G1 _V_E2;
  G1 _h_random;
  G1::mul(_V_E2, authority_pk, _temp_randomness);
  G1::mul(_h_random, h, _randomnesses[1]);  // random1_gamma
  G1::add(_V_E2, _V_E2, _h_random);

  // Calculate c = hash(k || phi || E1 || E2 || V_k || V_phi || V_E1 || V_E2 || associated_data )
  cybozu::Sha256 digest_engine;
  digest_engine.update(proof.k.serializeToHexStr());
  digest_engine.update(proof.phi.serializeToHexStr());
  digest_engine.update(_E1.serializeToHexStr());
  digest_engine.update(_E2.serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  digest_engine.update(_V_E1.serializeToHexStr());
  digest_engine.update(_V_E2.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  proof.c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E1: " << _V_E1.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E2: " << _V_E2.serializeToHexStr() << std::endl;

  // Calculate Rs
  Fr _temp_r;
  Fr _secret_c;
  proof.rs.reserve(attributes.size() + 2);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_secret_c, _attribute_hashes[i], proof.c);
    Fr::sub(_temp_r, _randomnesses[i], _secret_c);
    proof.rs.push_back(_temp_r);
  }
  Fr::mul(_secret_c, _t, proof.c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 2], _secret_c);
  proof.rs.push_back(_temp_r);
  Fr::mul(_secret_c, _epsilon, proof.c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 1], _secret_c);
  proof.rs.push_back(_temp_r);

  // plaintext attributes
  proof.attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      proof.attributes.push_back("");
    }
    else {
      proof.attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
  proof.E1 = _E1;
  proof.E2 = _E2;
  return proof;
}

IdProof  // sig1, sig2, k, phi, c, rs, attributes
PSRequester::el_passo_prove_id_without_id_retrieval(const PSCredential& sig,
                                                    const std::vector<std::tuple<std::string, bool>> attributes,
                                                    const std::string& associated_data,
                                                    const std::string& service_name) const
{
  size_t maxAllowedAttrNum = m_pk.Yi.size();
  if (attributes.size() != maxAllowedAttrNum) {
    throw std::runtime_error("attribute size does not match");
  }

  IdProof proof;
  // new_sig = sig1^r, (sig2 + sig1^t)^r
  Fr _t, _r;
  _t.setByCSPRNG();
  _r.setByCSPRNG();
  G1::mul(proof.sig1, sig.sig1, _r);
  G1::mul(proof.sig2, sig.sig1, _t);
  G1::add(proof.sig2, proof.sig2, sig.sig2);
  G1::mul(proof.sig2, proof.sig2, _r);

  // phi = hash(service_name)^s
  G1 _service_hash;
  Fr _s;
  hashAndMapToG1(_service_hash, service_name);
  _s.setHashOf(std::get<0>(attributes[0]));
  G1::mul(proof.phi, _service_hash, _s);

  // k = XX * PI{ YYj^mj } * gg^t
  proof.k = m_pk.XX;
  Fr _attribute_hash;
  G2 _yy_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G2::mul(_yy_hash, m_pk.YYi[i], _attribute_hash);
      G2::add(proof.k, proof.k, _yy_hash);
    }
  }
  G2::mul(_yy_hash, m_pk.gg, _t);
  G2::add(proof.k, proof.k, _yy_hash);

  /** NIZK Prove:
   * Public Value: will be sent
   * * k = XX * PI{ YY_j^attribute_j } * gg^t
   * * phi = hash(domain)^s
   *
   * Public Random Value: will not be sent
   * * V_k = XX * PI{ YYj^random1_j } * gg^random_2
   * * V_phi = hash(domain)^random1_s
   *
   * c: will be sent
   * c = hash(k || phi || V_k || V_phi || associated_data )
   *
   * Rs: will be sent
   * * random1_j - attribute_j * c
   * * random2 - t * c
   */
  // V_k = XX * PI{ YYj^random1_j } * gg^random_2
  G2 _V_k = m_pk.XX;
  std::vector<Fr> _randomnesses;
  Fr _temp_randomness;
  G2 _yy_randomness;
  _randomnesses.reserve(attributes.size() + 1);
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _temp_randomness.setByCSPRNG();
      _randomnesses.push_back(_temp_randomness);
      G2::mul(_yy_randomness, m_pk.YYi[i], _temp_randomness);
      G2::add(_V_k, _V_k, _yy_randomness);
    }
  }
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness);  // random2
  G2::mul(_yy_randomness, m_pk.gg, _temp_randomness);
  G2::add(_V_k, _V_k, _yy_randomness);

  // V_phi = hash(domain)^random1_s
  G1 _V_phi;
  G1::mul(_V_phi, _service_hash, _randomnesses[0]);  // random1_s

  // Calculate c = hash(k || phi || V_k || V_phi || associated_data )
  cybozu::Sha256 digest_engine;
  digest_engine.update(proof.k.serializeToHexStr());
  digest_engine.update(proof.phi.serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  proof.c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;

  // Calculate Rs
  Fr _temp_r;
  Fr _secret_c;
  proof.rs.reserve(attributes.size() + 1);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_secret_c, _attribute_hashes[i], proof.c);
    Fr::sub(_temp_r, _randomnesses[i], _secret_c);
    proof.rs.push_back(_temp_r);
  }
  Fr::mul(_secret_c, _t, proof.c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 1], _secret_c);
  proof.rs.push_back(_temp_r);

  // plaintext attributes
  proof.attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      proof.attributes.push_back("");
    }
    else {
      proof.attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  // sig1, sig2, k, phi, c, rs, attributes
  return proof;
}