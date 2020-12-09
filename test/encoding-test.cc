#include <ps-encoding.h>
#include <ps-requester.h>
#include <ps-signer.h>
#include <ps-verifier.h>
#include <iostream>

using namespace mcl::bls12;
char m_buf[128];

void
test_ps_buffer_encoding()
{
  std::cout << "****test_ps_buffer_encoding Start****" << std::endl;
  PSBuffer buffer;
  G1 g;
  G2 gg;
  Fr num;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  num.setByCSPRNG();
  std::vector<G1> g1List;
  std::vector<G2> g2List;
  std::vector<Fr> frList;
  for (size_t i = 0; i < 10; i++) {
    g1List.push_back(g);
    g2List.push_back(gg);
    frList.push_back(num);
  }
  buffer.appendG1Element(g);
  buffer.appendG2Element(gg);
  buffer.appendFrElement(num);
  buffer.appendG1Element(g, false);
  buffer.appendG2Element(gg, false);
  buffer.appendFrElement(num, false);
  buffer.appendG1List(g1List);
  buffer.appendG2List(g2List);
  buffer.appendFrList(frList);
  G1 newg;
  G2 newgg;
  Fr newnum;
  auto step = buffer.parseG1Element(0, newg);
  step += buffer.parseG2Element(step, newgg);
  step += buffer.parseFrElement(step, newnum);
  if (g != newg || gg != newgg || num != newnum) {
    std::cout << "test_ps_buffer_encoding append with type failure" << std::endl;
    return;
  }
  step += buffer.parseG1Element(step, newg, false);
  step += buffer.parseG2Element(step, newgg, false);
  step += buffer.parseFrElement(step, newnum, false);
  if (g != newg || gg != newgg || num != newnum) {
    std::cout << "test_ps_buffer_encoding append without type failure" << std::endl;
    return;
  }
  std::vector<G1> newg1List;
  std::vector<G2> newg2List;
  std::vector<Fr> newfrList;
  step += buffer.parseG1List(step, newg1List);
  step += buffer.parseG2List(step, newg2List);
  step += buffer.parseFrList(step, newfrList);
  if (newg1List.size() != 10 || newg2List.size() != 10 || newfrList.size() != 10) {
    std::cout << "test_ps_buffer_encoding list failure" << std::endl;
    return;
  }
  for (size_t i = 0; i < 10; i++) {
    if (newg1List[i] != g || newg2List[i] != gg || newfrList[i] != num) {
      std::cout << "test_ps_buffer_encoding num failure" << std::endl;
    return;
    }
  }
  std::cout << "****test_ps_buffer_encoding without errors****" << std::endl;
}

void
test_pk_with_different_attr_num()
{
  std::cout << "****test_pk_with_different_attr_num Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");

  Fr num;
  num.setByCSPRNG();

  size_t size = g.serialize(m_buf, sizeof(m_buf));
  std::cout << "G1 element size: " << size << std::endl;
  size = gg.serialize(m_buf, sizeof(m_buf));
  std::cout << "G2 element size: " << size << std::endl;
  size = num.serialize(m_buf, sizeof(m_buf));
  std::cout << "Fr element size: " << size << std::endl;

  PSSigner idp(3, g, gg);
  PSPubKey pubKey = idp.key_gen();
  std::cout << "3 total attributes. Public Key Size: " << pubKey.toBufferString().size() << std::endl;

  PSPubKey newKey = PSPubKey::fromBufferString(pubKey.toBufferString());
  if (newKey.g != pubKey.g || newKey.XX != pubKey.XX) {
    std::cout << "test_pk_with_different_attr_num failure" << std::endl;
    return;
  }

  PSSigner idp2(20, g, gg);
  pubKey = idp2.key_gen();
  std::cout << "20 total attributes. Public Key Size: " << pubKey.toBufferString().size() << std::endl;
  std::cout << "****test_pk_with_different_attr_num ends without errors****\n" << std::endl;
}

// void
// test_ps_sign_verify()
// {
//   std::cout << "****test_ps_sign_verify Start****" << std::endl;
//   G1 g;
//   G2 gg;
//   hashAndMapToG1(g, "abc");
//   hashAndMapToG2(gg, "edf");
//   PSSigner idp(3, g, gg);
//   auto pubKey = idp.key_gen();
//   auto pk_msg = protobuf_encode_ps_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);

//   PSRequester user;
//   protobuf_decode_ps_pk(*pk_msg, pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
//   user.init_with_pk(pubKey);
//   std::vector<std::tuple<std::string, bool>> attributes;
//   attributes.push_back(std::make_tuple("secret1", true));
//   attributes.push_back(std::make_tuple("secret2", true));
//   attributes.push_back(std::make_tuple("plain1", false));
//   auto [request_A, request_c, request_rs, request_attributes] = user.el_passo_request_id(attributes, "hello");
//   auto request_msg = protobuf_encode_sign_request(request_A, request_c, request_rs, request_attributes);

//   protobuf_decode_sign_request(*request_msg, request_A, request_c, request_rs, request_attributes);
//   G1 sig1, sig2;
//   if (!idp.el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2)) {
//     std::cout << "sign request failure" << std::endl;
//     return;
//   }
//   auto credential_msg = protobuf_encode_ps_credential(sig1, sig2);

//   protobuf_decode_ps_credential(*credential_msg, sig1, sig2);
//   auto [ubld_sig1, ubld_sig2] = user.unblind_credential(sig1, sig2);
//   std::vector<std::string> all_attributes;
//   all_attributes.push_back("secret1");
//   all_attributes.push_back("secret2");
//   all_attributes.push_back("plain1");
//   if (!user.verify(ubld_sig1, ubld_sig2, all_attributes)) {
//     std::cout << "unblinded credential verification failure" << std::endl;
//     return;
//   }

//   auto [rand_sig1, rand_sig2] = user.randomize_credential(ubld_sig1, ubld_sig2);
//   if (!user.verify(rand_sig1, rand_sig2, all_attributes)) {
//     std::cout << "randomized credential verification failure" << std::endl;
//     return;
//   }
//   std::cout << "****test_ps_sign_verify ends without errors****\n"
//             << std::endl;
// }

// void
// test_el_passo(size_t total_attribute_num)
// {
//   std::cout << "****test_el_passo Start****" << std::endl;
//   G1 g;
//   G2 gg;
//   hashAndMapToG1(g, "abc");
//   hashAndMapToG2(gg, "edf");
//   PSSigner idp(total_attribute_num, g, gg);

//   // IDP-KeyGen
//   auto begin = std::chrono::steady_clock::now();
//   auto [pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi] = idp.key_gen();
//   auto end = std::chrono::steady_clock::now();
//   std::cout << "IDP-KeyGen over " << total_attribute_num << " attributes: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;
//   auto pk_msg = protobuf_encode_ps_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
//   std::cout << "Public Key Response Packet Size: " << pk_msg->SerializeAsString().size() << std::endl;

//   // User-RequestID
//   protobuf_decode_ps_pk(*pk_msg, pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
//   PSRequester user;
//   user.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
//   std::vector<std::tuple<std::string, bool>> attributes;
//   attributes.push_back(std::make_tuple("s", true));
//   attributes.push_back(std::make_tuple("gamma", true));
//   attributes.push_back(std::make_tuple("tp", false));
//   if (total_attribute_num >= 4) {
//     attributes.push_back(std::make_tuple("s-new", true));
//   }
//   begin = std::chrono::steady_clock::now();
//   auto [request_A, request_c, request_rs, request_attributes] = user.el_passo_request_id(attributes, "hello");
//   end = std::chrono::steady_clock::now();
//   std::cout << "User-RequestID: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;
//   auto request_msg = protobuf_encode_sign_request(request_A, request_c, request_rs, request_attributes);
//   std::cout << "Setup Request Packet Size: " << request_msg->SerializeAsString().size() << std::endl;

//   // IDP-ProvideID
//   protobuf_decode_sign_request(*request_msg, request_A, request_c, request_rs, request_attributes);
//   G1 sig1, sig2;
//   begin = std::chrono::steady_clock::now();
//   bool sign_result = idp.el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2);
//   end = std::chrono::steady_clock::now();
//   std::cout << "IDP-ProvideID: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;
//   auto credential_msg = protobuf_encode_ps_credential(sig1, sig2);
//   std::cout << "Setup Response Packet Size: " << credential_msg->SerializeAsString().size() << std::endl;
//   if (!sign_result) {
//     std::cout << "sign request failure" << std::endl;
//     return;
//   }

//   // User-UnblindID
//   protobuf_decode_ps_credential(*credential_msg, sig1, sig2);
//   begin = std::chrono::steady_clock::now();
//   auto [ubld_sig1, ubld_sig2] = user.unblind_credential(sig1, sig2);
//   end = std::chrono::steady_clock::now();
//   std::cout << "User-UnblindID: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;

//   // User-ProveID
//   G1 authority_pk;
//   G1 h;
//   hashAndMapToG1(authority_pk, "ghi");
//   hashAndMapToG1(h, "jkl");
//   begin = std::chrono::steady_clock::now();
//   auto [prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
//         prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes] =
//       user.el_passo_prove_id(ubld_sig1, ubld_sig2, attributes, "hello", "service", authority_pk, g, h);
//   end = std::chrono::steady_clock::now();
//   std::cout << "User-ProveID: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;
//   auto prove_id_msg = protobuf_encode_id_proof(prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
//                                                prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes);
//   std::cout << "Sign-on Request Packet Size: " << prove_id_msg->SerializeAsString().size() << std::endl;

//   // RP-VerifyID
//   protobuf_decode_id_proof(*prove_id_msg, prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
//                            prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes);
//   PSVerifier rp;
//   rp.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
//   begin = std::chrono::steady_clock::now();
//   bool result = rp.el_passo_verify_id(
//       prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
//       prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes,
//       "hello", "service", authority_pk, g, h);
//   end = std::chrono::steady_clock::now();
//   std::cout << "RP-VerifyID: "
//             << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//             << "[µs]" << std::endl;

//   if (!result) {
//     std::cout << "EL PASSO Verify ID failed" << std::endl;
//   }

//   std::cout << "****test_el_passo ends without errors****\n"
//             << std::endl;
// }

int
main(int argc, char const *argv[])
{
  initPairing();
  test_ps_buffer_encoding();
  test_pk_with_different_attr_num();
  // test_el_passo(3);
  // test_el_passo(4);
}
