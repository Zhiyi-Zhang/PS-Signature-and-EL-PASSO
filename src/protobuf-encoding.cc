#include "protobuf-encoding.h"

char buf[1024];

void
protobuf_decode_ps_credential(const PSCredential& credential, G1& sig1, G1& sig2)
{
  const auto& sig1_str = credential.sig1();
  const auto& sig2_str = credential.sig2();
  sig1.deserialize(sig1_str.c_str(), sig1_str.size());
  sig2.deserialize(sig2_str.c_str(), sig2_str.size());
}

std::shared_ptr<PSCredential>
protobuf_encode_ps_credential(const G1& sig1, const G1& sig2)
{
  auto credential = std::make_shared<PSCredential>();
  size_t size = sig1.serialize(buf, sizeof(buf));
  credential->set_sig1(buf, size);
  size = sig2.serialize(buf, sizeof(buf));
  credential->set_sig2(buf, size);
  return credential;
}

void
protobuf_decode_ps_pk(const PSPubKey& pk, G1& g, G2& gg, G2& XX, std::vector<G1>& Yi, std::vector<G2>& YYi)
{
  Yi.clear();
  YYi.clear();
  Yi.reserve(pk.yi_size());
  YYi.reserve(pk.yyi_size());
  // g, gg, and XX
  const auto& g_str = pk.g();
  const auto& gg_str = pk.gg();
  const auto& XX_str = pk.xx();
  g.deserialize(g_str.c_str(), g_str.size());
  gg.deserialize(gg_str.c_str(), gg_str.size());
  XX.deserialize(XX_str.c_str(), XX_str.size());
  // Yi and YYi
  G1 Y;
  G2 YY;
  for (int i = 0; i < pk.yi_size(); i++) {
    const auto& Y_str = pk.yi()[i];
    const auto& YY_str = pk.yyi()[i];
    Y.deserialize(Y_str.c_str(), Y_str.size());
    YY.deserialize(YY_str.c_str(), YY_str.size());
    Yi.push_back(Y);
    YYi.push_back(YY);
  }
}

std::shared_ptr<PSPubKey>
protobuf_encode_ps_pk(const G1& g, const G2& gg, const G2& XX, const std::vector<G1>& Yi, const std::vector<G2>& YYi)
{
  auto pk = std::make_shared<PSPubKey>();
  // public key encoding
  // g
  size_t size = g.serialize(buf, sizeof(buf));
  pk->set_g(buf, size);
  // gg
  size = gg.serialize(buf, sizeof(buf));
  pk->set_gg(buf, size);
  // XX
  size = XX.serialize(buf, sizeof(buf));
  pk->set_xx(buf, size);
  // Y and YY for each attribute
  for (const auto& y : Yi) {
    size = y.serialize(buf, sizeof(buf));
    pk->add_yi(buf, size);
  }
  // YY for each attribute
  for (const auto& yy : YYi) {
    size = yy.serialize(buf, sizeof(buf));
    pk->add_yyi(buf, size);
  }
  return pk;
}

std::shared_ptr<PSCredRequest>
protobuf_encode_sign_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                             const std::vector<std::string>& attributes)
{
  auto request = std::make_shared<PSCredRequest>();
  // public key encoding
  // A
  size_t size = A.serialize(buf, sizeof(buf));
  request->set_a(buf, size);
  // c
  size = c.serialize(buf, sizeof(buf));
  request->set_c(buf, size);
  // rs
  for (const auto& r : rs) {
    size = r.serialize(buf, sizeof(buf));
    request->add_rs(buf, size);
  }
  // attributes
  for (const auto& attribute : attributes) {
    request->add_attributes(attribute);
  }
  return request;
}

void
protobuf_decode_sign_request(const PSCredRequest& request, G1& A, Fr& c, std::vector<Fr>& rs,
                             std::vector<std::string>& attributes)
{
  rs.clear();
  attributes.clear();
  rs.reserve(request.rs_size());
  attributes.reserve(request.attributes_size());
  // A, c
  const auto& A_str = request.a();
  const auto& c_str = request.c();
  A.deserialize(A_str.c_str(), A_str.size());
  c.deserialize(c_str.c_str(), c_str.size());
  // rs
  Fr _temp_r;
  for (int i = 0; i < request.rs_size(); i++) {
    const auto& r_str = request.rs()[i];
    _temp_r.deserialize(r_str.c_str(), r_str.size());
    rs.push_back(_temp_r);
  }
  // attributes
  for (int i = 0; i < request.attributes_size(); i++) {
    attributes.push_back(request.attributes()[i]);
  }
}

std::shared_ptr<ProveID>
protobuf_encode_prove_id(const G1& sig1, const G1& sig2, const G2& k, const G1& phi,
                         const G1& E1, const G1& E2, const Fr& c,
                         const std::vector<Fr>& rs, const std::vector<std::string>& attributes)
{
  auto prove_id = std::make_shared<ProveID>();
  // sig 1 and sig 2
  size_t size = sig1.serialize(buf, sizeof(buf));
  prove_id->set_sig1(buf, size);
  size = sig2.serialize(buf, sizeof(buf));
  prove_id->set_sig2(buf, size);
  // k
  size = k.serialize(buf, sizeof(buf));
  prove_id->set_k(buf, size);
  // phi
  size = phi.serialize(buf, sizeof(buf));
  prove_id->set_phi(buf, size);
  // E1 and E2
  size = E1.serialize(buf, sizeof(buf));
  prove_id->set_e1(buf, size);
  size = E2.serialize(buf, sizeof(buf));
  prove_id->set_e2(buf, size);
  // c
  size = c.serialize(buf, sizeof(buf));
  prove_id->set_c(buf, size);
  // rs
  for (const auto& r : rs) {
    size = r.serialize(buf, sizeof(buf));
    prove_id->add_rs(buf, size);
  }
  // YY for each attribute
  for (const auto& attribute : attributes) {
    prove_id->add_attributes(attribute);
  }
  return prove_id;
}

void
protobuf_decode_prove_id(const ProveID& prove_id, G1& sig1, G1& sig2, G2& k, G1& phi,
                         G1& E1, G1& E2, Fr& c,
                         std::vector<Fr>& rs, std::vector<std::string>& attributes)
{
  rs.clear();
  rs.reserve(prove_id.rs_size());
  attributes.clear();
  attributes.reserve(prove_id.attributes_size());
  // sig 1 and sig 2
  const auto& sig1_str = prove_id.sig1();
  const auto& sig2_str = prove_id.sig2();
  sig1.deserialize(sig1_str.c_str(), sig1_str.size());
  sig2.deserialize(sig2_str.c_str(), sig2_str.size());
  // k
  const auto& k_str = prove_id.k();
  k.deserialize(k_str.c_str(), k_str.size());
  // phi
  const auto& phi_str = prove_id.phi();
  phi.deserialize(phi_str.c_str(), phi_str.size());
  // E1 and E2
  const auto& e1_str = prove_id.e1();
  const auto& e2_str = prove_id.e2();
  E1.deserialize(e1_str.c_str(), e1_str.size());
  E2.deserialize(e2_str.c_str(), e2_str.size());
  // c
  const auto& c_str = prove_id.c();
  c.deserialize(c_str.c_str(), c_str.size());
  // rs
  Fr _temp_r;
  for (int i = 0; i < prove_id.rs_size(); i++) {
    const auto& r_str = prove_id.rs()[i];
    _temp_r.deserialize(r_str.c_str(), r_str.size());
    rs.push_back(_temp_r);
  }
  // attributes
  for (int i = 0; i < prove_id.attributes_size(); i++) {
    attributes.push_back(prove_id.attributes()[i]);
  }
}