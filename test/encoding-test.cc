#include <ps.h>
#include <protobuf-encoding.h>
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
  auto pk_msg = protobuf_encode_ps_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);

  PSRequester user;
  protobuf_decode_ps_pk(*pk_msg, pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  user.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("secret1", true));
  attributes.push_back(std::make_tuple("secret2", true));
  attributes.push_back(std::make_tuple("plain1", false));
  auto [request_A, request_c, request_rs, request_attributes] = user.generate_request(attributes, "hello");
  auto request_msg = protobuf_encode_sign_request(request_A, request_c, request_rs, request_attributes);

  protobuf_decode_sign_request(*request_msg, request_A, request_c, request_rs, request_attributes);
  G1 sig1, sig2;
  if (!idp.sign_cred_request(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2)) {
    std::cout << "sign request failure" << std::endl;
    return;
  }
  auto credential_msg = protobuf_encode_ps_credential(sig1, sig2);

  protobuf_decode_ps_credential(*credential_msg, sig1, sig2);
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

// void
// test_nizk_schnorr()
// {
//   std::cout << "****test_nizk_schnorr Start****" << std::endl;
//   // prepare
//   G1 g;
//   Fr secret;
//   hashAndMapToG1(g, "abc", 3);
//   secret.setByCSPRNG();
//   // test
//   G1 A, V;
//   Fr r;
//   nizk_schnorr_prove_fr(g, secret, "hello", A, V, r);
//   bool result = nizk_schnorr_verify_fr(g, A, V, r, "hello");
//   if (!result) {
//     std::cout << "NIZK schnorr failure" << std::endl;
//     return;
//   }
//   std::cout << "****test_nizk_schnorr ends without errors****\n" << std::endl;
// }

// void
// test_nizk_schnorr_with_two_bases()
// {
//   std::cout << "****test_nizk_schnorr_with_two_bases Start****" << std::endl;
//   // prepare
//   G1 g, h;
//   Fr secret1, secret2;
//   hashAndMapToG1(g, "abc", 3);
//   hashAndMapToG1(h, "def", 3);
//   secret1.setByCSPRNG();
//   secret2.setByCSPRNG();
//   // test
//   G1 A, V;
//   Fr r1, r2;
//   nizk_schnorr_prove_with_two_bases(g, h, secret1, secret2, "hello", A, V, r1, r2);
//   bool result = nizk_schnorr_verify_with_two_bases(g, h, A, V, r1, r2, "hello");
//   if (!result) {
//     std::cout << "NIZK schnorr verification failure" << std::endl;
//     return;
//   }
//   std::cout << "****test_nizk_schnorr_with_two_bases ends without errors****\n" << std::endl;
// }

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

  // auto [cred3, proof] = user.zk_prove_credentail(*cred2, c_attributes, attributes, "abc");
  // PSRequester user2;
  // user2.init_with_pk(pk);
  // if (!user2.zk_verify_credential(*cred3, *proof, "abc")) {
  //   std::cout << "zk verification failure" << std::endl;
  //   return;
  // }

  // G1 authority_pk_g1;
  // hashAndMapToG1(authority_pk_g1, "authority_pk");
  // char buffer[1024] = {0};
  // size_t size = authority_pk_g1.serialize(buffer, sizeof(buffer));
  // G1Point authority_pk;
  // authority_pk.set_g(buffer, size);
  // G1 h;
  // hashAndMapToG1(g, "random1");
  // hashAndMapToG1(h, "random2");
  // auto [cred4, proof2, audit_info] = user.zk_prove_credentail_with_accountability(*cred2, c_attributes, attributes, "hello", authority_pk, "secret1", g, h);
  // if (!user2.zk_verify_credential_with_accountability(*cred4, *proof2, *audit_info, authority_pk, "hello")) {
  //   std::cout << "accountability zk verification failure" << std::endl;
  //   return;
  // }
//   std::cout << "****test_zk_sig_prove ends without errors****\n" << std::endl;
// }

int main(int argc, char const *argv[])
{
  initPairing();
  test_ps_sign_verify();
}
