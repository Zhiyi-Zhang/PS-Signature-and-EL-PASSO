#include "ps-signer.h"

#include <chrono>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

PSSigner::PSSigner(size_t attribute_num)
    : m_attribute_num(attribute_num)
{
  m_pk.Yi.reserve(m_attribute_num);
  m_pk.YYi.reserve(m_attribute_num);
  Fr temp;
  temp.setByCSPRNG();
  hashAndMapToG1(m_pk.g, temp.serializeToHexStr());
  temp.setByCSPRNG();
  hashAndMapToG2(m_pk.gg, temp.serializeToHexStr());
}

PSSigner::PSSigner(size_t attribute_num, const G1& g, const G2& gg)
    : m_attribute_num(attribute_num)
{
  m_pk.g = g;
  m_pk.gg = gg;
  m_pk.Yi.reserve(m_attribute_num);
  m_pk.YYi.reserve(m_attribute_num);
}

PSPubKey  // g, gg, XX, Yi, YYi
PSSigner::key_gen()
{
  // generate private key
  // m_x
  Fr _sk_x;
  _sk_x.setByCSPRNG();
  // m_X
  G1::mul(m_sk_X, m_pk.g, _sk_x);

  // generate public key
  // public key: XX
  G2::mul(m_pk.XX, m_pk.gg, _sk_x);

  // public key: Y and YY for each attribute
  Fr y_item;
  G1 Y_item;
  G2 YY_item;
  for (size_t i = 0; i < m_attribute_num; i++) {
    y_item.setByCSPRNG();
    G1::mul(Y_item, m_pk.g, y_item);
    m_pk.Yi.push_back(Y_item);
    G2::mul(YY_item, m_pk.gg, y_item);
    m_pk.YYi.push_back(YY_item);
  }
  return m_pk;
}

PSPubKey
PSSigner::get_pub_key() const
{
  return m_pk;
}

bool
PSSigner::el_passo_provide_id(const PSCredRequest& request,
                              const std::string& associated_data, PSCredential& sig) const
{
  if (!el_passo_nizk_verify_request(request, associated_data)) {
    return false;
  }
  sig = sign_hybrid(request.A, request.attributes);
  return true;
}

bool
PSSigner::el_passo_nizk_verify_request(const PSCredRequest& request,
                                       const std::string& associated_data) const
{
  // NIZK proof
  // V: A^c * g^r0 * Yi^ri
  // true if hash( A || V || associated_data ) = c
  // prepare V
  G1 _V;
  G1::mul(_V, request.A, request.c);
  G1 _temp;
  G1::mul(_temp, m_pk.g, request.rs[0]);
  G1::add(_V, _V, _temp);
  int j = 1;
  for (size_t i = 0; i < request.attributes.size(); i++) {
    if (request.attributes[i] == "") {
      G1::mul(_temp, m_pk.Yi[i], request.rs[j]);
      j++;
      G1::add(_V, _V, _temp);
    }
  }
  // prepare c
  Fr _m_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(request.A.serializeToHexStr());
  digest_engine.update(_V.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _m_c.setHashOf(_c_str);
  // std::cout << "sign: A: " << request.A.serializeToHexStr() << std::endl;
  // std::cout << "sign: V: " << _V.serializeToHexStr() << std::endl;
  // std::cout << "sign: c: " << _m_c.serializeToHexStr() << std::endl;
  // check if NIZK verification is successful
  if (_m_c != request.c) {
    return false;
  }
  return true;
}

PSCredential
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
    G1::mul(_temp_yi_hash, m_pk.Yi[i], _temp_hash);
    G1::add(_final_A, _final_A, _temp_yi_hash);
  }
  return this->sign_commitment(_final_A);
}

PSCredential
PSSigner::sign_commitment(const G1& commitment) const
{
  Fr u;
  u.setByCSPRNG();

  PSCredential sig;
  // sig 1
  G1::mul(sig.sig1, m_pk.g, u);
  // sig 2
  G1::add(sig.sig2, m_sk_X, commitment);
  G1::mul(sig.sig2, sig.sig2, u);

  return sig;
}