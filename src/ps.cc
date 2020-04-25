#include "ps.h"
#include <cybozu/sha2.hpp>

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
  for (int i = 0; i < m_attribute_num; i++) {
    y_item.setByCSPRNG();
    G1::mul(Y_item, m_g, y_item);
    m_pk_Yi.push_back(Y_item);
    G2::mul(YY_item, m_gg, y_item);
    m_pk_YYi.push_back(YY_item);
  }
  return std::make_tuple(m_g, m_gg, m_pk_XX, m_pk_Yi, m_pk_YYi);
}

// std::shared_ptr<PSPubKey>
// PSSigner::key_gen()
// {
//   auto [_g, _gg, _XX, _Yi, _YYi] = key_gen_as_tuple();
//   return _encode_pk(_g, _gg, _XX, _Yi, _YYi);
// }

bool
PSSigner::sign_cred_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                            const std::vector<std::string>& plaintext_attributes,
                            const std::string& associated_data, G1& sig1, G1& sig2) const
{
  if (!nizk_verify_request(A, c, rs, plaintext_attributes, associated_data)) {
    return false;
  }
  std::tie(sig1, sig2) = sign_hybrid(A, plaintext_attributes);
  return true;
}

// std::shared_ptr<PSCredential>
// PSSigner::sign_cred_request(const PSCredRequest& request, const std::string& associated_data) const
// {
//   G1 _A;
//   Fr _c;
//   std::vector<Fr> _rs;
//   std::vector<std::string> _plaintext_attributes;
//   _parse_sign_request(request, _A, _c, _rs, _plaintext_attributes);
//   if (!nizk_verify_request(_A, _c, _rs, _plaintext_attributes, associated_data)) {
//     return nullptr;
//   }
//   G1 _sig1, _sig2;
//   std::tie(_sig1, _sig2) = sign_hybrid(_A, _plaintext_attributes);
//   auto sig = std::make_shared<PSCredential>();
//   _generate_credential(_sig1, _sig2, sig);
//   return sig;
// }

bool
PSSigner::nizk_verify_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                              const std::vector<std::string>& plaintext_attributes,
                              const std::string& associated_data) const
{
  // NIZK proof
  // V: A^c * g^r0 * Yi^ri
  // true if hash( A || V || associated_data ) = c
  // prepare V
  G1 _V;
  G1::mul(_V, A, c);
  G1 _temp;
  for (int i = 0; i < rs.size(); i++) {
    if (i == 0) {
      _temp = m_g;
    }
    else {
      _temp = m_pk_Yi[i - 1];
    }
    G1::mul(_temp, _temp, rs[i]);
    G1::add(_V, _V, _temp);
  }
  // prepare c
  Fr _m_c;
  cybozu::Sha256 digest_engine;
  digest_engine.update(A.serializeToHexStr());
  digest_engine.update(_V.serializeToHexStr());
  auto _c_str = digest_engine.digest(associated_data);
  _m_c.setHashOf(_c_str);
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
  for (int i = 0; i < attributes.size(); i++) {
    _temp_hash.setHashOf(attributes[attributes.size() - 1 - i]);
    G1::mul(_temp_yi_hash, m_pk_Yi[m_pk_Yi.size() - 1 - i], _temp_hash);
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

// void
// PSRequester::init_with_pk(const std::shared_ptr<PSPubKey>& pk)
// {
//   _parse_pk(*pk, m_g, m_gg, m_pk_XX, m_pk_Yi, m_pk_YYi);
// }

std::tuple<G1, Fr, std::vector<Fr>, std::vector<std::string>> // A, c, r, plaintext_attributes
PSRequester::generate_request(const std::vector<std::string> attributes_to_commitment,
                              const std::vector<std::string> plaintext_attributes,
                              const std::string& associated_data)
{
  // NIZK Prove:
  // Public Value: A = g^t * PI{Yi^(attribute_i)}, will be sent
  // Public Random Value: V = g^random1 * PI{Yi^(random2_i)}, will not be sent
  // c = hash( A || V || associated_data);, will be sent
  // r0 = random1 - t*c; r1 = random2_i - attribute_i * c, will be sent

  // parameters to send:
  G1 _A;
  Fr _c;
  std::vector<Fr> _rs;
  _rs.reserve(attributes_to_commitment.size() + 1);
  // Prepare A
  m_t1.setByCSPRNG();
  G1::mul(_A, m_g, m_t1);
  Fr _attribute_hash;
  G1 _Yi_hash;
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(attributes_to_commitment.size());
  for (int i = 0; i < attributes_to_commitment.size(); i++) {
    _attribute_hash.setHashOf(attributes_to_commitment[i]);
    _attribute_hashes.push_back(_attribute_hash);
    G1::mul(_Yi_hash, m_pk_Yi[i], _attribute_hash);
    G1::add(_A, _A, _Yi_hash);
  }
  // Prepare randomness
  std::vector<Fr> _randomnesses;
  _randomnesses.reserve(attributes_to_commitment.size() + 1);
  Fr _temp_randomness;
  for (int i = 0; i < 1 + attributes_to_commitment.size(); i++) {
    _temp_randomness.setByCSPRNG();
    _randomnesses.push_back(_temp_randomness);
  }
  // Calculate V
  G1 _V;
  G1::mul(_V, m_g, _randomnesses[0]);
  for (int i = 1; i < _randomnesses.size(); i++) {
    G1::mul(_Yi_hash, m_pk_Yi[i - 1], _randomnesses[i]);
    G1::add(_V, _V, _Yi_hash);
  }
  // Calculate c
  cybozu::Sha256 digest_engine;
  digest_engine.update(_A.serializeToHexStr());
  std::cout << "parepare: A: " << _A.serializeToHexStr() << std::endl;
  digest_engine.update(_V.serializeToHexStr());
  std::cout << "parepare: V: " << _V.serializeToHexStr() << std::endl;
  auto _c_str = digest_engine.digest(associated_data);
  _c.setHashOf(_c_str);
  std::cout << "parepare: c: " << _c.serializeToHexStr() << std::endl;
  // Calculate rs
  Fr _r_temp;
  Fr::mul(_r_temp, m_t1, _c);
  Fr::sub(_r_temp, _randomnesses[0], _r_temp);
  _rs.push_back(_r_temp);
  for (int i = 0; i < _attribute_hashes.size(); i++) {
    Fr::mul(_r_temp, _attribute_hashes[i], _c);
    Fr::sub(_r_temp, _randomnesses[i + 1], _r_temp);
    _rs.push_back(_r_temp);
  }
  // return
  return std::make_tuple(_A, _c, _rs, plaintext_attributes);
}

// std::shared_ptr<PSCredRequest>
// PSRequester::generate_request(const std::vector<std::string> attributes_to_commitment,
//                               const std::vector<std::string> plaintext_attributes,
//                               const std::string& associated_data)
// {
//   auto [_A, _c, _rs, _plaintext_attributes] = generate_request_as_tuple(attributes_to_commitment, plaintext_attributes, associated_data);
//   auto request = std::make_shared<PSCredRequest>();
//   return _encode_sign_request(_A, _c, _rs, _plaintext_attributes);
// }

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

// std::shared_ptr<PSCredential>
// PSRequester::unblind_credential(const PSCredential& credential) const
// {
//   // unblinded_sig <- (sig_1, sig_2 - t*sig_1)
//   G1 sig1, sig2;
//   _parse_credential(credential, sig1, sig2);

//   G1 t_sig1;
//   G1 unblinded_sig2;
//   G1::mul(t_sig1, sig1, m_t1);
//   G1::sub(unblinded_sig2, sig2, t_sig1);

//   auto unblinded = std::make_shared<PSCredential>();
//   _generate_credential(sig1, unblinded_sig2, unblinded);
//   return unblinded;
// }

bool
PSRequester::verify(const G1& sig1, const G1& sig2, const std::vector<std::string>& all_attributes) const
{
  std::vector<Fr> _attribute_hashes;
  _attribute_hashes.reserve(all_attributes.size());
  Fr _attribute_hash;
  for (const auto& attribute : all_attributes) {
    _attribute_hash.setHashOf(attribute);
    _attribute_hashes.push_back(_attribute_hash);
  }

  if (sig1.isZero()) {
    return false;
  }

  G2 _yy_hash_sum = m_pk_XX;
  int counter = 0;
  G2 _yyi_hash_product;
  for (const auto& hash : _attribute_hashes) {
    G2::mul(_yyi_hash_product, m_pk_YYi[counter], hash);
    G2::add(_yy_hash_sum, _yy_hash_sum, _yyi_hash_product);
    counter++;
  }

  GT _lhs, _rhs;
  pairing(_lhs, sig1, _yy_hash_sum);
  pairing(_rhs, sig2, m_gg);
  return _lhs == _rhs;
}

// bool
// PSRequester::verify(const PSCredential& credential, const std::list<std::string>& attributes) const
// {
//   std::list<Fr> attribute_hashes;
//   Fr attribute_hash;
//   for (const auto& attribute : attributes) {
//     attribute_hash.setHashOf(attribute);
//     attribute_hashes.push_back(attribute_hash);
//   }

//   G1 sig1, sig2;
//   _parse_credential(credential, sig1, sig2);

//   if (sig1.isZero()) {
//     return false;
//   }

//   G2 yy_hash_sum = m_pk_XX;
//   int counter = 0;
//   G2 pk_yyi;
//   G2 yyi_hash_product;
//   for (const auto& hash : attribute_hashes) {
//     pk_yyi = m_pk_YYi[counter];
//     G2::mul(yyi_hash_product, pk_yyi, hash);
//     G2::add(yy_hash_sum, yy_hash_sum, yyi_hash_product);
//     counter++;
//   }

//   GT lhs, rhs;
//   pairing(lhs, sig1, yy_hash_sum);
//   pairing(rhs, sig2, m_gg);
//   return lhs == rhs;
// }


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

// std::shared_ptr<PSCredential>
// PSRequester::randomize_credential(const PSCredential& credential)
// {
//   G1 sig1, sig2;
//   _parse_credential(credential, sig1, sig2);

//   Fr t;
//   t.setByCSPRNG();
//   G1::mul(sig1, sig1, t);
//   G1::mul(sig2, sig2, t);

//   auto randomized = std::make_shared<PSCredential>();
//   _generate_credential(sig1, sig2, randomized);
//   return randomized;
// }

// std::tuple<std::shared_ptr<PSCredential>, std::shared_ptr<PSCredProof>>
// PSRequester::zk_prove_credentail(const PSCredential& credential,
//                                  const std::list<std::string> attributes_to_commitment,
//                                  const std::list<std::string> plaintext_attributes,
//                                  const std::string& associated_data)
// {
//   G1 sig1, sig2;
//   _parse_credential(credential, sig1, sig2);

//   // new_sig = (r*sig1, r*(sig2 + t*sig1))
//   auto randomized = std::make_shared<PSCredential>();
//   G1 new_sig1, new_sig2;
//   Fr t, r;
//   t.setByCSPRNG();
//   r.setByCSPRNG();
//   G1::mul(new_sig1, sig1, r);
//   G1::mul(sig1, sig1, t);
//   G1::add(sig2, sig2, sig1);
//   G1::mul(new_sig2, sig2, r);
//   _generate_credential(new_sig1, new_sig2, randomized);

//   auto proof = std::make_shared<PSCredProof>();
//   const auto& base = new_sig1;

//   // proofs: the first A,V,r is for t*g, the rest are for attributes
//   std::list<G1> As;
//   std::list<G1> Vs;
//   std::list<Fr> rs;
//   G1 A;
//   G1 V;
//   Fr attribute_hash;
//   nizk_schnorr_prove_fr(base, t, associated_data, A, V, r);
//   size_t size = A.serialize(buf, sizeof(buf));
//   proof->add_as(buf, size);
//   size = V.serialize(buf, sizeof(buf));
//   proof->add_vs(buf, size);
//   size = r.serialize(buf, sizeof(buf));
//   proof->add_rs(buf, size);
//   for (const auto& attribute : attributes_to_commitment) {
//     attribute_hash.setHashOf(attribute);
//     nizk_schnorr_prove_fr(base, attribute_hash, associated_data, A, V, r);
//     size = A.serialize(buf, sizeof(buf));
//     proof->add_as(buf, size);
//     size = V.serialize(buf, sizeof(buf));
//     proof->add_vs(buf, size);
//     size = r.serialize(buf, sizeof(buf));
//     proof->add_rs(buf, size);
//   }
//   // plaintext attributes
//   for (const auto& attribute : plaintext_attributes) {
//     proof->add_attributes(attribute);
//   }
//   return std::make_tuple(randomized, proof);
// }

// bool
// PSRequester::zk_verify_credential(const PSCredential& credential, const PSCredProof& proof,
//                                   const std::string& associated_data)
// {
//   // needed elements
//   G1 ele_3_l;
//   G2 ele_1_r, ele_3_r;
//   GT ele_1, ele_2, ele_3;
//   // parse signature
//   G1 sig1, sig2;
//   _parse_credential(credential, sig1, sig2);
//   // nizk verify
//   G1 A, V;
//   Fr r;
//   G2 yyi;
//   GT ele_2_i;
//   for (int i = 0; i < proof.as_size(); i++) {
//     const auto& A_string = proof.as()[i];
//     A.deserialize(A_string.c_str(), A_string.size());
//     const auto& V_string = proof.vs()[i];
//     V.deserialize(V_string.c_str(), V_string.size());
//     const auto& r_string = proof.rs()[i];
//     r.deserialize(r_string.c_str(), r_string.size());
//     if (!nizk_schnorr_verify_fr(sig1, A, V, r, associated_data)) {
//       return false;
//     }
//     if (i == 0) {
//       ele_3_l = A;
//     }
//     else {
//       pairing(ele_2_i, A, m_pk_YYi[i - 1]);
//       if (i == 1) {
//         ele_2 = ele_2_i;
//       }
//       else {
//         GT::mul(ele_2, ele_2, ele_2_i);
//       }
//     }
//   }
//   Fr attribute_hash;
//   G1 sig_attribute;
//   for (int i = 0; i < proof.attributes_size(); i++) {
//     attribute_hash.setHashOf(proof.attributes()[i]);
//     G1::mul(sig_attribute, sig1, attribute_hash);
//     pairing(ele_2_i, sig_attribute, m_pk_YYi[proof.as_size() - 1 + i]);
//     GT::mul(ele_2, ele_2, ele_2_i);
//   }
//   // verification
//   GT lh, rh;
//   pairing(ele_1, sig1, m_pk_XX);
//   pairing(ele_3, ele_3_l, m_gg);
//   GT::mul(lh, ele_1, ele_2);
//   GT::mul(lh, lh, ele_3);
//   pairing(rh, sig2, m_gg);
//   return lh == rh;
// }

// std::tuple<std::shared_ptr<PSCredential>, std::shared_ptr<PSCredProof>, std::shared_ptr<IdRecoveryToken>>
// PSRequester::zk_prove_credentail_with_accountability(const PSCredential& credential,
//                                                      const std::list<std::string> attributes_to_commitment,
//                                                      const std::list<std::string> plaintext_attributes,
//                                                      const std::string& associated_data,
//                                                      const G1Point& authority_pk,
//                                                      const std::string& attribute_for_audit,
//                                                      const G1& g, const G1& h)
// {
//   // prepare El Gamal ciphertext and its NIZK proof
//   G1 m_pk;
//   const auto pk_str = authority_pk.g();
//   m_pk.deserialize(pk_str.c_str(), pk_str.size());
//   Fr m_r, m_attribute;
//   m_r.setByCSPRNG();
//   m_attribute.setHashOf(attribute_for_audit);
//   auto id_recovery_token = std::make_shared<IdRecoveryToken>();
//   size_t size = g.serialize(buf, sizeof(buf));
//   id_recovery_token->set_g(buf, size);
//   size = h.serialize(buf, sizeof(buf));
//   id_recovery_token->set_h(buf, size);
//   // NIZK proof of El Gamal ciphertext
//   G1 V, A;
//   Fr m_r1, m_r2;
//   // c1
//   nizk_schnorr_prove_fr(g, m_r, associated_data, A, V, m_r1);
//   size = A.serialize(buf, sizeof(buf));
//   id_recovery_token->add_as(buf, size);
//   size = V.serialize(buf, sizeof(buf));
//   id_recovery_token->add_vs(buf, size);
//   size = m_r1.serialize(buf, sizeof(buf));
//   id_recovery_token->add_rs(buf, size);
//   // c2
//   nizk_schnorr_prove_with_two_bases(m_pk, h, m_r, m_attribute, associated_data, A, V, m_r1, m_r2);
//   size = A.serialize(buf, sizeof(buf));
//   id_recovery_token->add_as(buf, size);
//   size = V.serialize(buf, sizeof(buf));
//   id_recovery_token->add_vs(buf, size);
//   size = m_r1.serialize(buf, sizeof(buf));
//   id_recovery_token->add_rs(buf, size);
//   size = m_r2.serialize(buf, sizeof(buf));
//   id_recovery_token->add_rs(buf, size);
//   auto [cred, proof] = this->zk_prove_credentail(credential, attributes_to_commitment, plaintext_attributes, associated_data);
//   return std::make_tuple(cred, proof, id_recovery_token);
// }

// bool
// PSRequester::zk_verify_credential_with_accountability(const PSCredential& credential, const PSCredProof& proof,
//                                                       const IdRecoveryToken& id_recovery_token,
//                                                       const G1Point& authority_pk, const std::string& associated_data)
// {
//   G1 m_pk;
//   const auto pk_str = authority_pk.g();
//   m_pk.deserialize(pk_str.c_str(), pk_str.size());
//   // parse audit info
//   bool result = false;
//   G1 g, h;
//   const auto& g_str = id_recovery_token.g();
//   const auto& h_str = id_recovery_token.h();
//   g.deserialize(g_str.c_str(), g_str.size());
//   h.deserialize(h_str.c_str(), h_str.size());
//   // NIZK verify
//   G1 m_A, m_V;
//   Fr m_r1, m_r2;
//   for (int i = 0; i < id_recovery_token.as_size(); i++) {
//     const auto& a_str = id_recovery_token.as()[i];
//     m_A.deserialize(a_str.c_str(), a_str.size());
//     const auto& v_str = id_recovery_token.vs()[i];
//     m_V.deserialize(v_str.c_str(), v_str.size());
//     const auto& r_str = id_recovery_token.rs()[i];
//     m_r1.deserialize(r_str.c_str(), r_str.size());
//     if (i == 0) {
//       result = nizk_schnorr_verify_fr(g, m_A, m_V, m_r1, associated_data);
//     }
//     else {
//       const auto& r2_str = id_recovery_token.rs()[i + 1];
//       m_r2.deserialize(r2_str.c_str(), r2_str.size());
//       result = result && nizk_schnorr_verify_with_two_bases(m_pk, h, m_A, m_V, m_r1, m_r2, associated_data);
//     }
//   }
//   return zk_verify_credential(credential, proof, associated_data) && result;
// }