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
  m_x.setRand();
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
  std::list<Fp> ys;
  Fp y_item;
  for (int i = 0; i < attribute_num; i++) {
    y_item.setRand();
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
PSSigner::sign_cred_request(const std::shared_ptr<PSCredRequest> request) const
{
  // gt
  G1 gt;
  const auto& gt_buf = request->gt();
  gt.deserialize(gt_buf.c_str(), gt_buf.size());
  // commitmented attributes
  std::list<G1> c_attributes;
  G1 c_attribute;
  G1 base;
  G1 V;
  Fp r;
  for (int i = 0; i < request->c_attributes_size(); i++) {
    const auto& c_attribute_buf = request->c_attributes()[i];
    c_attribute.deserialize(c_attribute_buf.c_str(), c_attribute_buf.size());
    c_attributes.push_back(c_attribute);
    // NIZK schnorr protocol
    const auto& base_buf = m_pk->yi()[i];
    base.deserialize(base_buf.c_str(), base_buf.size());
    const auto& V_buf = request->vs()[i];
    V.deserialize(V_buf.c_str(), V_buf.size());
    const auto& r_buf = request->rs()[i];
    r.deserialize(r_buf.c_str(), r_buf.size());
    bool pass = nizk_schnorr_verify(base, c_attribute, V, r, "replace_with_your_id");
    if (!pass) {
      return nullptr;
    }
  }
  // plaintext attributes
  std::list<std::string> attributes;
  for (int i = 0; i < request->c_attributes_size(); i++) {
    attributes.push_back(request->attributes()[i]);
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
  Fp hash;
  int counter = 0;
  for (const auto& attribute : attributes) {
    const auto& encoded = m_pk->yi()[counter];
    base.deserialize(encoded.c_str(), encoded.size());
    hash.setHashOf(attribute);
    G1::mul(after_commitment, base, hash);
    G1::add(commitment, commitment, after_commitment);
  }
  return this->sign_commitment(commitment);
}

std::shared_ptr<PSCredential>
PSSigner::sign_commitment(const G1& commitment) const
{
  Fp u;
  u.setRand();
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
  size = sig1.serialize(buf, sizeof(buf));
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
  m_t.setRand();
  G1 gt;
  size_t size = gt.serialize(buf, sizeof(buf));
  request->set_gt(buf, size);
  // attributes to commitment and schnorr protocol parameters
  G1 after_commitment;
  G1 base;
  G1 V;
  Fp attribute_hash;
  Fp c;
  Fp v;
  Fp r;
  Fp ac;
  std::string schnorr_hash_str;
  cybozu::Sha256 digest_engine;
  int counter = 0;
  for (const auto& attribute : attributes_to_commit) {
    // commitmented attribute
    const auto& encoded = m_pk->yi()[counter];
    base.deserialize(encoded.c_str(), encoded.size());
    attribute_hash.setHashOf(attribute);
    G1::mul(after_commitment, base, attribute_hash);
    size = after_commitment.serialize(buf, sizeof(buf));
    request->add_c_attributes(buf, size);
    // non-interactive schnorr protocol: V
    v.setRand();
    G1::mul(V, base, v);
    size = V.serialize(buf, sizeof(buf));
    request->add_vs(buf, size);
    // non-interactive schnorr protocol: r
    digest_engine.clear();
    digest_engine.update(base.serializeToHexStr());
    digest_engine.update(V.serializeToHexStr());
    digest_engine.update(after_commitment.serializeToHexStr());
    schnorr_hash_str = digest_engine.digest("replace_with_your_id");
    c.setHashOf(schnorr_hash_str);
    Fp::mul(ac, attribute_hash, c);
    Fp::sub(r, v, ac);
    size = r.serialize(buf, sizeof(buf));
    request->add_rs(buf, size);
  }
  // plaintext attributes
  for (const auto& attribute : plaintext_attributes) {
    request->add_attributes(attribute);
  }
  return request;
}

std::shared_ptr<PSCredential>
PSRequester::unblind_credential(const PSCredential& credential)
{
  return nullptr;
}