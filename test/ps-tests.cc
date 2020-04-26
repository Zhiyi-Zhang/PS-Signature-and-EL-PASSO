#include <ps.h>
#include <nizk-schnorr.h>
#include <iostream>

using namespace mcl::bls12;

void
test_ps_sign_verify()
{
  std::cout << "****test_ps_sign_verify Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(3, g, gg);
  auto [pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi] = idp.key_gen();

  PSRequester user;
  user.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("secret1", true));
  attributes.push_back(std::make_tuple("secret2", true));
  attributes.push_back(std::make_tuple("plain1", false));
  auto [request_A, request_c, request_rs, request_attributes] = user.generate_request(attributes, "hello");

  G1 sig1, sig2;
  if (!idp.sign_cred_request(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2)) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  auto [ubld_sig1, ubld_sig2] = user.unblind_credential(sig1, sig2);
  std::vector<std::string> all_attributes;
  all_attributes.push_back("secret1");
  all_attributes.push_back("secret2");
  all_attributes.push_back("plain1");
  if (!user.verify(ubld_sig1, ubld_sig2, all_attributes)) {
    std::cout << "unblinded credential verification failure" << std::endl;
    return;
  }

  auto [rand_sig1, rand_sig2] = user.randomize_credential(ubld_sig1, ubld_sig2);
  if (!user.verify(rand_sig1, rand_sig2, all_attributes)) {
    std::cout << "randomized credential verification failure" << std::endl;
    return;
  }
  std::cout << "****test_ps_sign_verify ends without errors****\n" << std::endl;
}

void
test_el_passo()
{
  std::cout << "****test_el_passo Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(3, g, gg);
  auto [pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi] = idp.key_gen();

  PSRequester user;
  user.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("s", true));
  attributes.push_back(std::make_tuple("gamma", true));
  attributes.push_back(std::make_tuple("tp", false));
  auto [request_A, request_c, request_rs, request_attributes] = user.generate_request(attributes, "hello");

  G1 sig1, sig2;
  if (!idp.sign_cred_request(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2)) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  auto [ubld_sig1, ubld_sig2] = user.unblind_credential(sig1, sig2);

  G1 authority_pk;
  G1 h;
  hashAndMapToG1(authority_pk, "ghi");
  hashAndMapToG1(h, "jkl");
  auto [prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
        prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes] =
      user.el_passo_prove_id(ubld_sig1, ubld_sig2, attributes, "hello", "service", authority_pk, g, h);

  PSRequester rp;
  rp.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);

  bool result = rp.el_passo_verify_id(
      prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
      prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes,
      "hello", "service", authority_pk, g, h);

  if (!result) {
    std::cout << "EL PASSO Verify ID failed" << std::endl;
  }

  std::cout << "****test_el_passo ends without errors****\n" << std::endl;
}

// void
// test_zk_sig_prove()
// {
//   std::cout << "****test_zk_sig_prove Start****" << std::endl;
//   G1 g;
//   G2 gg;
//   hashAndMapToG1(g, "abc");
//   hashAndMapToG2(gg, "edf");
//   PSSigner idp(3, g, gg);
//   auto pk = idp.key_gen();

//   PSRequester user;
//   user.init_with_pk(pk);
//   std::vector<std::string> c_attributes;
//   c_attributes.push_back("secret1");
//   c_attributes.push_back("secret2");
//   std::vector<std::string> attributes;
//   attributes.push_back("plain1");
//   auto request = user.generate_request(c_attributes, attributes, "hello");

//   auto cred1 = idp.sign_cred_request(*request, "hello");
//   if (cred1 == nullptr) {
//     std::cout << "sign request failure" << std::endl;
//   }

//   auto cred2 = user.unblind_credential(*cred1);
//   std::list<std::string> all_attributes;
//   all_attributes.push_back("secret1");
//   all_attributes.push_back("secret2");
//   all_attributes.push_back("plain1");
//   if (!user.verify(*cred2, all_attributes)) {
//     std::cout << "unblinded credential verification failure" << std::endl;
//     return;
//   }
//   std::cout << "****test_zk_sig_prove ends without errors****\n" << std::endl;
// }

int
main(int argc, char const *argv[])
{
  initPairing();
  test_ps_sign_verify();
  test_el_passo();
}
