#include "ps.h"
#include <cybozu/sha2.hpp>
#include <chrono>

using namespace mcl::bls12;

/*==============PSSigner==============*/

PSSigner::PSSigner(size_t attribute_num, const G1& g, const G2& gg)
  : m_attribute_num(attribute_num)
  , m_g(g)
  , m_gg(gg)
{
  m_pk_Yi.reserve(m_attribute_num);
  m_pk_YYi.reserve(m_attribute_num);
}

std::tuple<G1, G2, G2, std::vector<G1>, std::vector<G2>> // g, gg, XX, Yi, YYi
PSSigner::key_gen()
{
  // generate private key
  // m_x
  m_sk_x.setByCSPRNG();
  // m_X
  G1::mul(m_sk_X, m_g, m_sk_x);

  // generate public key
  // public key: XX
  G2::mul(m_pk_XX, m_gg, m_sk_x);

  // public key: Y and YY for each attribute
  Fr y_item;
  G1 Y_item;
  G2 YY_item;
  for (size_t i = 0; i < m_attribute_num; i++) {
    y_item.setByCSPRNG();
    G1::mul(Y_item, m_g, y_item);
    m_pk_Yi.push_back(Y_item);
    G2::mul(YY_item, m_gg, y_item);
    m_pk_YYi.push_back(YY_item);
  }
  return std::make_tuple(m_g, m_gg, m_pk_XX, m_pk_Yi, m_pk_YYi);
}

bool
PSSigner::sign_cred_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                            const std::vector<std::string>& attributes,
                            const std::string& associated_data, G1& sig1, G1& sig2) const
{
  if (!nizk_verify_request(A, c, rs, attributes, associated_data)) {
    return false;
  }
  std::tie(sig1, sig2) = sign_hybrid(A, attributes);
  return true;
}

bool
PSSigner::nizk_verify_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                              const std::vector<std::string>& attributes,
                              const std::string& associated_data) const
{
  // NIZK proof
  // V: A^c * g^r0 * Yi^ri
  // true if hash( A || V || associated_data ) = c
  // prepare V
  G1 _V;
  G1::mul(_V, A, c);
  G1 _temp;
  G1::mul(_temp, m_g, rs[0]);
  G1::add(_V, _V, _temp);
  int j = 1;
  for (size_t i = 0; i < attributes.size(); i++) {
    if (attributes[i] == "") {
      G1::mul(_temp, m_pk_Yi[i], rs[j]);
      j++;
      G1::add(_V, _V, _temp);
    }
  }
  // prepare c
  Fr _m_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(A.serializeToHexStr());
  digest_engine.update(_V.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _m_c.setHashOf(_c_str);
  // std::cout << "sign: A: " << A.serializeToHexStr() << std::endl;
  // std::cout << "sign: V: " << _V.serializeToHexStr() << std::endl;
  // std::cout << "sign: c: " << _m_c.serializeToHexStr() << std::endl;
  // check if NIZK verification is successful
  if (_m_c != c) {
    return false;
  }
  return true;
}

std::tuple<G1, G1>
PSSigner::sign_hybrid(const G1& A, const std::vector<std::string>& attributes) const
{
  G1 _final_A = A;
  G1 _temp_yi_hash;
  Fr _temp_hash;
  for (size_t i = 0; i < attributes.size(); i++) {
    if (attributes[i] == "") {
      continue;
    }
    _temp_hash.setHashOf(attributes[i]);
    G1::mul(_temp_yi_hash, m_pk_Yi[i], _temp_hash);
    G1::add(_final_A, _final_A, _temp_yi_hash);
  }
  return this->sign_commitment(_final_A);
}

std::tuple<G1, G1>
PSSigner::sign_commitment(const G1& commitment) const
{
  Fr u;
  u.setByCSPRNG();

  // sig 1
  G1 sig1;
  G1::mul(sig1, m_g, u);
  // sig 2
  G1 sig2;
  G1::add(sig2, m_sk_X, commitment);
  G1::mul(sig2, sig2, u);

  return std::make_tuple(sig1, sig2);
}

/*==============PSRequester==============*/

PSRequester::PSRequester()
{}

void
PSRequester::init_with_pk(const G1& g, const G2& gg, const G2& XX,
                          const std::vector<G1>& Yi, const std::vector<G2>& YYi)
{
  m_g = g;
  m_gg = gg;
  m_pk_XX = XX;
  m_pk_Yi = Yi;
  m_pk_YYi = YYi;
}

std::tuple<G1, Fr, std::vector<Fr>, std::vector<std::string>>
PSRequester::generate_request(const std::vector<std::tuple<std::string, bool>> attributes, // string is the attribute, bool whether to hide
                              const std::string& associated_data)
{
  /** NIZK Prove:
   * Public Value: A = g^t * PI{Yi^(attribute_i)}, will be sent
   * Public Random Value: V = g^random1 * PI{Yi^(random2_i)}, will not be sent
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
  G1::mul(_A, m_g, m_t1);
  Fr _attribute_hash;
  G1 _Yi_hash, _Yi_randomness;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  // Parepare for randomness
  std::vector<Fr> _randomnesses;
  _randomnesses.reserve(attributes.size() + 1);
  Fr _temp_randomness;
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness); // the randomness for g^t
  // prepare for V
  G1 _V;
  G1::mul(_V, m_g, _temp_randomness);
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      // this attribute needs to be commitmented
      // calculate A
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G1::mul(_Yi_hash, m_pk_Yi[i], _attribute_hash);
      G1::add(_A, _A, _Yi_hash);
      // generate randomness
      _temp_randomness.setByCSPRNG();
      _randomnesses.push_back(_temp_randomness); // the randomness for message i
      // calculate V
      G1::mul(_Yi_randomness, m_pk_Yi[i], _temp_randomness);
      G1::add(_V, _V, _Yi_randomness);
    }
  }
  // Calculate c
  cybozu::Sha256 digest_engine;
  digest_engine.update(_A.serializeToHexStr());
  // std::cout << "parepare: A: " << _A.serializeToHexStr() << std::endl;
  digest_engine.update(_V.serializeToHexStr());
  // std::cout << "parepare: V: " << _V.serializeToHexStr() << std::endl;
  auto _c_str = digest_engine.digest(associated_data);
  _c.setHashOf(_c_str);
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
  G2 _yy_hash_sum = m_pk_XX;
  int counter = 0;
  G2 _yyi_hash_product;
  for (const auto& attribute : all_attributes) {
    _attribute_hash.setHashOf(attribute);
    G2::mul(_yyi_hash_product, m_pk_YYi[counter], _attribute_hash);
    G2::add(_yy_hash_sum, _yy_hash_sum, _yyi_hash_product);
    counter++;
  }

  GT _lhs, _rhs;
  pairing(_lhs, sig1, _yy_hash_sum);
  pairing(_rhs, sig2, m_gg);
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

std::tuple<G1, G1, G2, G1, G1, G1, Fr, std::vector<Fr>, std::vector<std::string>> // sig1, sig2, k, phi, E1, E2, c, rs, attributes
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
  G2 _k = m_pk_XX;
  Fr _attribute_hash;
  G2 _yy_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes.size());
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _attribute_hash.setHashOf(std::get<0>(attributes[i]));
      _attribute_hashes.push_back(_attribute_hash);
      G2::mul(_yy_hash, m_pk_YYi[i], _attribute_hash);
      G2::add(_k, _k, _yy_hash);
    }
  }
  G2::mul(_yy_hash, m_gg, _t);
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
  G2 _V_k = m_pk_XX;
  std::vector<Fr> _randomnesses;
  Fr _temp_randomness;
  G2 _yy_randomness;
  _randomnesses.reserve(attributes.size() + 2);
  for (size_t i = 0; i < attributes.size(); i++) {
    if (std::get<1>(attributes[i])) {
      _temp_randomness.setByCSPRNG();
      _randomnesses.push_back(_temp_randomness);
      G2::mul(_yy_randomness, m_pk_YYi[i], _temp_randomness);
      G2::add(_V_k, _V_k, _yy_randomness);
    }
  }
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness); // random2
  G2::mul(_yy_randomness, m_gg, _temp_randomness);
  G2::add(_V_k, _V_k, _yy_randomness);

  // V_phi
  G1 _V_phi;
  G1::mul(_V_phi, _service_hash, _randomnesses[0]); // random1_s

  // V_E1 = g^random_3
  G1 _V_E1;
  _temp_randomness.setByCSPRNG();
  _randomnesses.push_back(_temp_randomness); // random 3
  G1::mul(_V_E1, g, _temp_randomness);

  // V_E2 = y^random_3 * h^random1_gamma
  G1 _V_E2;
  G1 _h_random;
  G1::mul(_V_E2, authority_pk, _temp_randomness);
  G1::mul(_h_random, h, _randomnesses[1]); // random1_gamma
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

bool
PSRequester::el_passo_verify_id(const G1& sig1, const G1& sig2, const G2& k, const G1& phi,
                                const G1& E1, const G1& E2, const Fr& c,
                                const std::vector<Fr>& rs, const std::vector<std::string>& attributes,
                                const std::string& associated_data,
                                const std::string& service_name,
                                const G1& authority_pk, const G1& g, const G1& h)
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
   *       = k^c * XX^(1-c) * PI{ YYj^r1_j } ** gg^r2
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
  // V_k = k^c * XX^(1-c) * PI{ YYj^r1_j } ** gg^r2
  G2 _V_k;
  G2::mul(_V_k, k, c);
  int counter = 0;
  G2 _base_r;
  for (size_t i = 0; i < attributes.size(); i++) {
    if (attributes[i] == "") {
      G2::mul(_base_r, m_pk_YYi[i], rs[counter]);
      counter++;
      G2::add(_V_k, _V_k, _base_r);
    }
  }
  G2::mul(_base_r, m_gg, rs[rs.size() - 2]);
  G2::add(_V_k, _V_k, _base_r);
  Fr _1_c = Fr::one();
  Fr::sub(_1_c, _1_c, c);
  G2::mul(_base_r, m_pk_XX, _1_c);
  G2::add(_V_k, _V_k, _base_r);

  // V_phi = phi^c * hash(domain)^r1_s
  G1 _V_phi, _V_E1, _V_E2;
  G1::mul(_V_phi, phi, c);
  G1 _temp;
  hashAndMapToG1(_temp, service_name);
  G1::mul(_temp, _temp, rs[0]);
  G1::add(_V_phi, _V_phi, _temp);

  // V_E1 = E1^c * g^r3
  G1::mul(_V_E1, E1, c);
  G1::mul(_temp, g, rs[rs.size() - 1]);
  G1::add(_V_E1, _V_E1, _temp);

  // V_E2 = E2^c * y^r3 * h^r1_gamma
  G1::mul(_V_E2, E2, c);
  G1::mul(_temp, authority_pk, rs[rs.size() - 1]);
  G1::add(_V_E2, _V_E2, _temp);
  G1::mul(_temp, h, rs[1]);
  G1::add(_V_E2, _V_E2, _temp);

  // Calculate c = hash(k || phi || E1 || E2 || V_k || V_phi || V_E1 || V_E2 || associated_data )
  Fr _local_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(k.serializeToHexStr());
  digest_engine.update(phi.serializeToHexStr());
  digest_engine.update(E1.serializeToHexStr());
  digest_engine.update(E2.serializeToHexStr());
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

  if (c != _local_c) {
    return false;
  }

  // signature verification, e(sigma’_1, k) ?= e(sigma’_2, gg)
  G2 _final_k = prepare_hybrid_verification(k, attributes);
  GT lhs, rhs;
  pairing(lhs, sig1, _final_k);
  pairing(rhs, sig2, m_gg);
  return lhs == rhs;
}

G2
PSRequester::prepare_hybrid_verification(const G2& k, const std::vector<std::string>& attributes) const
{
  G2 _final_k = k;
  G2 _temp_yyi_hash;
  Fr _temp_hash;
  for (size_t i = 0; i < attributes.size(); i++) {
    if (attributes[i] == "") {
      continue;
    }
    _temp_hash.setHashOf(attributes[i]);
    G2::mul(_temp_yyi_hash, m_pk_YYi[i], _temp_hash);
    G2::add(_final_k, _final_k, _temp_yyi_hash);
  }
  return _final_k;
}
