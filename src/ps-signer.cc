#include "ps-signer.h"

#include <chrono>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

PSSigner::PSSigner(size_t attribute_num)
    : m_attribute_num(attribute_num)
{
  m_pk_Yi.reserve(m_attribute_num);
  m_pk_YYi.reserve(m_attribute_num);
  Fr temp;
  temp.setByCSPRNG();
  hashAndMapToG1(m_g, temp.serializeToHexStr());
  temp.setByCSPRNG();
  hashAndMapToG2(m_gg, temp.serializeToHexStr());
}

PSSigner::PSSigner(size_t attribute_num, const G1& g, const G2& gg)
    : m_attribute_num(attribute_num)
    , m_g(g)
    , m_gg(gg)
{
  m_pk_Yi.reserve(m_attribute_num);
  m_pk_YYi.reserve(m_attribute_num);
}

std::tuple<G1, G2, G2, std::vector<G1>, std::vector<G2>>  // g, gg, XX, Yi, YYi
PSSigner::key_gen()
{
  // generate private key
  // m_x
  Fr _sk_x;
  _sk_x.setByCSPRNG();
  // m_X
  G1::mul(m_sk_X, m_g, _sk_x);

  // generate public key
  // public key: XX
  G2::mul(m_pk_XX, m_gg, _sk_x);

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

std::tuple<G1, G2, G2, std::vector<G1>, std::vector<G2>>
PSSigner::get_pub_key()
{
  return std::make_tuple(m_g, m_gg, m_pk_XX, m_pk_Yi, m_pk_YYi);
}

bool
PSSigner::el_passo_provide_id(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                              const std::vector<std::string>& attributes,
                              const std::string& associated_data, G1& sig1, G1& sig2) const
{
  if (!el_passo_nizk_verify_request(A, c, rs, attributes, associated_data)) {
    return false;
  }
  std::tie(sig1, sig2) = sign_hybrid(A, attributes);
  return true;
}

bool
PSSigner::el_passo_nizk_verify_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
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
PSSigner::sign_hybrid(const G1& commitment, const std::vector<std::string>& attributes) const
{
  if (attributes.size() == 1) {
    return this->sign_commitment(commitment);
  }
  G1 _final_A = commitment;
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