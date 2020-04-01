#include "ps.hpp"
char buf[1024];
using namespace mcl::bls12;

PS::PS()
{
  initPairing();
}

std::shared_ptr<PK>
PS::key_gen(const std::list<std::string>& attributes)
{
  auto pk = std::make_shared<PK>();
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
  for (int i = 0; i < attributes.size(); i++) {
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
  return pk;
}

std::shared_ptr<SIG>
PS::sign_hybrid(const PK& pk, const G1& gt, const G1& c_attributes, const std::list<std::string>& attributes)
{
  
}

std::shared_ptr<SIG>
PS::sign_commitment(const PK& pk, const G1& commitment)
{
  Fp u;
  u.setRand();
  // sig 1
  auto sig = std::make_shared<SIG>();
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
}
