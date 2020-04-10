#include "ps.h"
#include "nizk-schnorr.h"

char buf[1024];
using namespace mcl::bls12;

/*==============PSSigner==============*/

PSSigner::PSSigner()
{
}

std::shared_ptr<PSPubKey>
PSSigner::key_gen(int attribute_num)
{
  auto pk = std::make_shared<PSPubKey>();
  // private key
  // g
  hashAndMapToG1(m_g, "abc", 3); // TODO: use random bits
  size_t size = m_g.serialize(buf, sizeof(buf));
  pk->set_g(buf, size);
  // x
  m_x.setByCSPRNG();
  // X
  G1::mul(m_X, m_g, m_x);

  // public key
  // gg
  hashAndMapToG2(m_gg, "def", 3); // TODO: use random bits
  size = m_gg.serialize(buf, sizeof(buf));
  pk->set_gg(buf, size);
  // XX
  G2 XX;
  G2::mul(XX, m_gg, m_x);
  size = XX.serialize(buf, sizeof(buf));
  pk->set_xx(buf, size);
  // y for each attribute
  std::list<Fr> ys;
  Fr y_item;
  for (int i = 0; i < attribute_num; i++) {
    y_item.setByCSPRNG();
    ys.push_back(y_item);
  }
  // Y for each attribute
  G1 Y_item;
  for (const auto& y : ys) {
    G1::mul(Y_item, m_g, y);
    size = Y_item.serialize(buf, sizeof(buf));
    pk->add_yi(buf, size);
  }
  // YY for each attribute
  G2 YY_item;
  for (const auto& y : ys) {
    G2::mul(YY_item, m_gg, y);
    size = YY_item.serialize(buf, sizeof(buf));
    pk->add_yyi(buf, size);
  }
  m_pk = pk;
  return m_pk;
}

std::shared_ptr<PSCredential>
PSSigner::sign_cred_request(const PSCredRequest& request) const
{
  // gt
  G1 gt;
  const auto& gt_buf = request.gt();
  gt.deserialize(gt_buf.c_str(), gt_buf.size());
  // commitmented attributes
  std::list<G1> c_attributes;
  G1 c_attribute;
  G1 base;
  G1 V;
  Fr r;
  for (int i = 0; i < request.c_attributes_size(); i++) {
    // base
    const auto& base_buf = m_pk->yi()[i];
    base.deserialize(base_buf.c_str(), base_buf.size());
    // c_attribute
    const auto& c_attribute_buf = request.c_attributes()[i];
    c_attribute.deserialize(c_attribute_buf.c_str(), c_attribute_buf.size());
    c_attributes.push_back(c_attribute);
    // V
    const auto& V_buf = request.vs()[i];
    V.deserialize(V_buf.c_str(), V_buf.size());
    // r
    const auto& r_buf = request.rs()[i];
    r.deserialize(r_buf.c_str(), r_buf.size());
    // NIZK schnorr verify
    bool pass = nizk_schnorr_verify(base, c_attribute, V, r, "replace_with_your_id");
    if (!pass) {
      return nullptr;
    }
  }
  // plaintext attributes
  std::list<std::string> attributes;
  for (int i = 0; i < request.attributes_size(); i++) {
    attributes.push_back(request.attributes()[i]);
  }
  return sign_hybrid(gt, c_attributes, attributes);
}

std::shared_ptr<PSCredential>
PSSigner::sign_hybrid(const G1& gt,
                      const std::list<G1>& c_attributes,
                      const std::list<std::string>& attributes) const
{
  G1 commitment = gt;
  for (const auto& attribute : c_attributes) {
    G1::add(commitment, commitment, attribute);
  }
  G1 after_commitment, base;
  Fr hash;
  int counter = 0;
  for (const auto& attribute : attributes) {
    const auto& encoded = m_pk->yi()[counter + c_attributes.size()];
    base.deserialize(encoded.c_str(), encoded.size());
    hash.setHashOf(attribute);
    G1::mul(after_commitment, base, hash);
    G1::add(commitment, commitment, after_commitment);
    counter++;
  }
  return this->sign_commitment(commitment);
}

std::shared_ptr<PSCredential>
PSSigner::sign_commitment(const G1& commitment) const
{
  Fr u;
  u.setByCSPRNG();
  // sig 1
  auto sig = std::make_shared<PSCredential>();
  G1 sig1;
  G1::mul(sig1, m_g, u);
  size_t size = sig1.serialize(buf, sizeof(buf));
  sig->set_sig1(buf, size);
  // sig 2
  G1 sig2_base, sig2;
  G1::add(sig2_base, m_X, commitment);
  G1::mul(sig2, sig2_base, u);
  size = sig2.serialize(buf, sizeof(buf));
  sig->set_sig2(buf, size);
  return sig;
}

/*==============PSRequester==============*/

PSRequester::PSRequester(const std::shared_ptr<PSPubKey>& pk)
  : m_pk(pk)
{
}

std::shared_ptr<PSCredRequest>
PSRequester::generate_request(const std::list<std::string> attributes_to_commit,
                              const std::list<std::string> plaintext_attributes)
{
  auto request = std::make_shared<PSCredRequest>();
  // gt
  m_t1.setByCSPRNG();
  G1 g;
  auto g_str = m_pk->g();
  g.deserialize(g_str.c_str(), g_str.size());
  G1 gt;
  G1::mul(gt, g, m_t1);
  size_t size = gt.serialize(buf, sizeof(buf));
  request->set_gt(buf, size);
  // attributes to commitment and schnorr protocol parameters
  G1 base;
  G1 after_commitment;
  G1 V;
  Fr attribute_hash;
  Fr r;
  int counter = 0;
  for (const auto& attribute : attributes_to_commit) {
    // base
    const auto& encoded = m_pk->yi()[counter];
    base.deserialize(encoded.c_str(), encoded.size());
    // commitmented attribute
    attribute_hash.setHashOf(attribute);
    // NIZK Shnorr prove
    nizk_schnorr_prove(base, attribute_hash, "replace_with_your_id", after_commitment, V, r);
    size = after_commitment.serialize(buf, sizeof(buf));
    request->add_c_attributes(buf, size);
    size = V.serialize(buf, sizeof(buf));
    request->add_vs(buf, size);
    size = r.serialize(buf, sizeof(buf));
    request->add_rs(buf, size);
    counter++;
  }
  // plaintext attributes
  for (const auto& attribute : plaintext_attributes) {
    request->add_attributes(attribute);
  }
  return request;
}

std::shared_ptr<PSCredential>
PSRequester::unblind_credential(const PSCredential& credential) const
{
  // unblinded_sig <- (sig_1, sig_2 - t*sig_1)
  G1 sig1, sig2;
  auto sig1_str = credential.sig1();
  auto sig2_str = credential.sig2();
  sig1.deserialize(sig1_str.c_str(), sig1_str.size());
  sig2.deserialize(sig2_str.c_str(), sig2_str.size());
  G1 t_sig1;
  G1 unblinded_sig2;
  G1::mul(t_sig1, sig1, m_t1);
  G1::sub(unblinded_sig2, sig2, t_sig1);

  size_t size = unblinded_sig2.serialize(buf, sizeof(buf));
  auto unblinded = std::make_shared<PSCredential>();
  unblinded->set_sig1(sig1_str);
  unblinded->set_sig2(buf, size);
  return unblinded;
}

bool
PSRequester::verify(const PSCredential& credential, const std::list<std::string>& attributes) const
{
  std::list<Fr> attribute_hashes;
  Fr attribute_hash;
  for (const auto& attribute : attributes) {
    attribute_hash.setHashOf(attribute);
    attribute_hashes.push_back(attribute_hash);
  }

  G1 sig1, sig2;
  auto sig1_str = credential.sig1();
  auto sig2_str = credential.sig2();
  sig1.deserialize(sig1_str.c_str(), sig1_str.size());
  sig2.deserialize(sig2_str.c_str(), sig2_str.size());

  if (sig1.isZero()) {
    return false;
  }

  G2 pk_xx;
  auto xx_str = m_pk->xx();
  pk_xx.deserialize(xx_str.c_str(), xx_str.size());
  G2 yy_hash_sum = pk_xx;
  int counter = 0;
  G2 pk_yyi;
  G2 yyi_hash_product;
  for (const auto& hash : attribute_hashes) {
    auto const pk_yyi_str = m_pk->yyi()[counter];
    pk_yyi.deserialize(pk_yyi_str.c_str(), pk_yyi_str.size());
    G2::mul(yyi_hash_product, pk_yyi, hash);
    G2::add(yy_hash_sum, yy_hash_sum, yyi_hash_product);
    counter++;
  }

  G2 pk_gg;
  auto pk_gg_str = m_pk->gg();
  pk_gg.deserialize(pk_gg_str.c_str(), pk_gg_str.size());

  GT lhs, rhs;
  pairing(lhs, sig1, yy_hash_sum);
  pairing(rhs, sig2, pk_gg);
  return lhs == rhs;
}

std::shared_ptr<PSCredential>
PSRequester::randomize_credential(const PSCredential& credential)
{
  G1 sig1, sig2;
  auto sig1_str = credential.sig1();
  auto sig2_str = credential.sig2();
  sig1.deserialize(sig1_str.c_str(), sig1_str.size());
  sig2.deserialize(sig2_str.c_str(), sig2_str.size());

  m_t2.setByCSPRNG();
  G1::mul(sig1, sig1, m_t2);
  G1::mul(sig2, sig2, m_t2);

  auto randomized = std::make_shared<PSCredential>();
  size_t size = sig1.serialize(buf, sizeof(buf));
  randomized->set_sig1(buf, size);
  size = sig2.serialize(buf, sizeof(buf));
  randomized->set_sig2(buf, size);
  return randomized;
}

std::shared_ptr<PSCredProof>
PSRequester::prove_credentail(const PSCredential& credential,
                              const std::list<std::string> attributes_to_commitment,
                              const std::list<std::string> plaintext_attributes)
{
  return nullptr;
}