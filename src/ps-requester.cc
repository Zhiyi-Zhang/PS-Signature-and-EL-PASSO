#include "ps-requester.h"

#include <chrono>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

PSRequester::PSRequester(const PSPubKey& pk)
    : m_pk(pk)
{
}

std::tuple<G1, Fr, std::vector<Fr>, std::vector<std::string>>
PSRequester::el_passo_request_id(const std::vector<std::tuple<std::string, bool>> attributes,  // string is the attribute, bool whether to hide
                                 const std::string& associated_data)
{
  /** NIZK Prove:
   * Public Value: A = g^t * PI{Yi^(attribute_i)}, will be sent
   * Public Random Value: V = g^random1 * PROD{Yi^(random2_i)}, will not be sent
   * c = hash( A || V || associated_data);, will be sent
   * r0 = random1 - t*c; r1 = random2_i - attribute_i * c, will be sent
   */

  // parameters to send:
  G1 _A;
  Fr _c;
  std::vector<Fr> _rs;
  _rs.reserve(attributes.size() + 1);
  // Prepare for A
  m_t1.setByCSPRNG();
  G1::mul(_A, m_pk.g, m_t1);
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
      G1::add(_A, _A, _Yi_hash);
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
  digest_engine.update(_A.serializeToHexStr());
  digest_engine.update(_V.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _c.setHashOf(_c_str);
  // std::cout << "parepare: A: " << _A.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V: " << _V.serializeToHexStr() << std::endl;
  // std::cout << "parepare: c: " << _c.serializeToHexStr() << std::endl;
  // Calculate rs
  Fr _r_temp;
  Fr::mul(_r_temp, m_t1, _c);
  Fr::sub(_r_temp, _randomnesses[0], _r_temp);
  _rs.push_back(_r_temp);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_r_temp, _attribute_hashes[i], _c);
    Fr::sub(_r_temp, _randomnesses[i + 1], _r_temp);
    _rs.push_back(_r_temp);
  }
  // plaintext attributes
  std::vector<std::string> _plaintext_attributes;
  _plaintext_attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _plaintext_attributes.push_back("");
    }
    else {
      _plaintext_attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  return std::make_tuple(_A, _c, _rs, _plaintext_attributes);
}

std::tuple<G1, G1>
PSRequester::unblind_credential(const G1& sig1, const G1& sig2) const
{
  // unblinded_sig <- (sig_1, sig_2 / sig_1^t)
  G1 _sig1_t;
  G1 _unblinded_sig2;
  G1::mul(_sig1_t, sig1, m_t1);
  G1::sub(_unblinded_sig2, sig2, _sig1_t);
  return std::make_tuple(sig1, _unblinded_sig2);
}

bool
PSRequester::verify(const G1& sig1, const G1& sig2, const std::vector<std::string>& all_attributes) const
{
  if (sig1.isZero()) {
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
  pairing(_lhs, sig1, _yy_hash_sum);
  pairing(_rhs, sig2, m_pk.gg);
  return _lhs == _rhs;
}

std::tuple<G1, G1>
PSRequester::randomize_credential(const G1& sig1, const G1& sig2) const
{
  G1 _new_sig1, _new_sig2;
  Fr t;
  t.setByCSPRNG();
  G1::mul(_new_sig1, sig1, t);
  G1::mul(_new_sig2, sig2, t);
  return std::make_tuple(_new_sig1, _new_sig2);
}

std::tuple<G1, G1, G2, G1, G1, G1, Fr, std::vector<Fr>, std::vector<std::string>>  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
PSRequester::el_passo_prove_id(const G1& sig1, const G1& sig2,
                               const std::vector<std::tuple<std::string, bool>> attributes,
                               const std::string& associated_data,
                               const std::string& service_name,
                               const G1& authority_pk, const G1& g, const G1& h)
{
  // new_sig = sig1^r, sig2 + sig1^t)^r
  G1 _new_sig1, _new_sig2;
  Fr _t, _r;
  _t.setByCSPRNG();
  _r.setByCSPRNG();
  G1::mul(_new_sig1, sig1, _r);
  G1::mul(_new_sig2, sig1, _t);
  G1::add(_new_sig2, _new_sig2, sig2);
  G1::mul(_new_sig2, _new_sig2, _r);

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
  G1 _phi;
  G1 _service_hash;
  Fr _s;
  hashAndMapToG1(_service_hash, service_name);
  _s.setHashOf(std::get<0>(attributes[0]));
  G1::mul(_phi, _service_hash, _s);

  // k = XX * PI{ YYj^mj } * gg^t
  G2 _k = m_pk.XX;
  Fr _attribute_hash;
  G2 _yy_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G2::mul(_yy_hash, m_pk.YYi[i], _attribute_hash);
      G2::add(_k, _k, _yy_hash);
    }
  }
  G2::mul(_yy_hash, m_pk.gg, _t);
  G2::add(_k, _k, _yy_hash);

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
  // V_k
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
  Fr _c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(_k.serializeToHexStr());
  digest_engine.update(_phi.serializeToHexStr());
  digest_engine.update(_E1.serializeToHexStr());
  digest_engine.update(_E2.serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  digest_engine.update(_V_E1.serializeToHexStr());
  digest_engine.update(_V_E2.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E1: " << _V_E1.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V E2: " << _V_E2.serializeToHexStr() << std::endl;

  // Calculate Rs
  std::vector<Fr> _rs;
  Fr _temp_r;
  Fr _secret_c;
  _rs.reserve(attributes.size() + 3);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_secret_c, _attribute_hashes[i], _c);
    Fr::sub(_temp_r, _randomnesses[i], _secret_c);
    _rs.push_back(_temp_r);
  }
  Fr::mul(_secret_c, _t, _c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 2], _secret_c);
  _rs.push_back(_temp_r);
  Fr::mul(_secret_c, _epsilon, _c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 1], _secret_c);
  _rs.push_back(_temp_r);

  // plaintext attributes
  std::vector<std::string> _plaintext_attributes;
  _plaintext_attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _plaintext_attributes.push_back("");
    }
    else {
      _plaintext_attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
  return std::make_tuple(_new_sig1, _new_sig2, _k, _phi, _E1, _E2, _c, _rs, _plaintext_attributes);
}

std::tuple<G1, G1, G2, G1, Fr, std::vector<Fr>, std::vector<std::string>>  // sig1, sig2, k, phi, c, rs, attributes
PSRequester::el_passo_prove_id_without_id_retrieval(const G1& sig1, const G1& sig2,
                                                    const std::vector<std::tuple<std::string, bool>> attributes,
                                                    const std::string& associated_data,
                                                    const std::string& service_name)
{
  // new_sig = sig1^r, sig2 + sig1^t)^r
  G1 _new_sig1, _new_sig2;
  Fr _t, _r;
  _t.setByCSPRNG();
  _r.setByCSPRNG();
  G1::mul(_new_sig1, sig1, _r);
  G1::mul(_new_sig2, sig1, _t);
  G1::add(_new_sig2, _new_sig2, sig2);
  G1::mul(_new_sig2, _new_sig2, _r);

  // phi = hash(service_name)^s
  G1 _phi;
  G1 _service_hash;
  Fr _s;
  hashAndMapToG1(_service_hash, service_name);
  _s.setHashOf(std::get<0>(attributes[0]));
  G1::mul(_phi, _service_hash, _s);

  // k = XX * PI{ YYj^mj } * gg^t
  G2 _k = m_pk.XX;
  Fr _attribute_hash;
  G2 _yy_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G2::mul(_yy_hash, m_pk.YYi[i], _attribute_hash);
      G2::add(_k, _k, _yy_hash);
    }
  }
  G2::mul(_yy_hash, m_pk.gg, _t);
  G2::add(_k, _k, _yy_hash);

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
  // V_k
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

  // V_phi
  G1 _V_phi;
  G1::mul(_V_phi, _service_hash, _randomnesses[0]);  // random1_s

  // Calculate c = hash(k || phi || V_k || V_phi || associated_data )
  Fr _c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(_k.serializeToHexStr());
  digest_engine.update(_phi.serializeToHexStr());
  digest_engine.update(_V_k.serializeToHexStr());
  digest_engine.update(_V_phi.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _c.setHashOf(_c_str);
  // std::cout << "parepare: V k: " << _V_k.serializeToHexStr() << std::endl;
  // std::cout << "parepare: V phi: " << _V_phi.serializeToHexStr() << std::endl;

  // Calculate Rs
  std::vector<Fr> _rs;
  Fr _temp_r;
  Fr _secret_c;
  _rs.reserve(attributes.size() + 1);
  for (size_t i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_secret_c, _attribute_hashes[i], _c);
    Fr::sub(_temp_r, _randomnesses[i], _secret_c);
    _rs.push_back(_temp_r);
  }
  Fr::mul(_secret_c, _t, _c);
  Fr::sub(_temp_r, _randomnesses[_randomnesses.size() - 1], _secret_c);
  _rs.push_back(_temp_r);

  // plaintext attributes
  std::vector<std::string> _plaintext_attributes;
  _plaintext_attributes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _plaintext_attributes.push_back("");
    }
    else {
      _plaintext_attributes.push_back(std::get<0>(attributes[i]));
    }
  }
  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
  return std::make_tuple(_new_sig1, _new_sig2, _k, _phi, _c, _rs, _plaintext_attributes);
}