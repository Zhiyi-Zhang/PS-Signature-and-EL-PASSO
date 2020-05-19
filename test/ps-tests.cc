#include <ps.h>

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
  auto [request_A, request_c, request_rs, request_attributes] = user.el_passo_request_id(attributes, "hello");

  G1 sig1, sig2;
  if (!idp.el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2)) {
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
  std::cout << "****test_ps_sign_verify ends without errors****\n"
            << std::endl;
}

void
test_el_passo(size_t total_attribute_num)
{
  std::cout << "****test_el_passo Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(total_attribute_num, g, gg);

  // IDP-KeyGen
  auto begin = std::chrono::steady_clock::now();
  auto [pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi] = idp.key_gen();
  auto end = std::chrono::steady_clock::now();
  std::cout << "IDP-KeyGen over " << total_attribute_num << " attributes: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // User-RequestID
  PSRequester user;
  user.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("s", true));
  attributes.push_back(std::make_tuple("gamma", true));
  attributes.push_back(std::make_tuple("tp", false));
  begin = std::chrono::steady_clock::now();
  auto [request_A, request_c, request_rs, request_attributes] = user.el_passo_request_id(attributes, "hello");
  end = std::chrono::steady_clock::now();
  std::cout << "User-RequestID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // IDP-ProvideID
  G1 sig1, sig2;
  begin = std::chrono::steady_clock::now();
  bool sign_result = idp.el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2);
  end = std::chrono::steady_clock::now();
  std::cout << "IDP-ProvideID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  if (!sign_result) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  // User-UnblindID
  begin = std::chrono::steady_clock::now();
  auto [ubld_sig1, ubld_sig2] = user.unblind_credential(sig1, sig2);
  end = std::chrono::steady_clock::now();
  std::cout << "User-UnblindID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // User-ProveID
  G1 authority_pk;
  G1 h;
  hashAndMapToG1(authority_pk, "ghi");
  hashAndMapToG1(h, "jkl");
  begin = std::chrono::steady_clock::now();
  auto [prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
        prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes] =
      user.el_passo_prove_id(ubld_sig1, ubld_sig2, attributes, "hello", "service", authority_pk, g, h);
  end = std::chrono::steady_clock::now();
  std::cout << "User-ProveID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // RP-VerifyID
  PSRequester rp;
  rp.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  begin = std::chrono::steady_clock::now();
  bool result = rp.el_passo_verify_id(
      prove_id_sig1, prove_id_sig2, prove_id_k, prove_id_phi, prove_id_E1,
      prove_id_E2, prove_id_c, prove_id_rs, prove_id_plaintext_attributes,
      "hello", "service", authority_pk, g, h);
  end = std::chrono::steady_clock::now();
  std::cout << "RP-VerifyID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  if (!result) {
    std::cout << "EL PASSO Verify ID failed" << std::endl;
  }

  std::cout << "****test_el_passo ends without errors****\n"
            << std::endl;
}

void
test_el_pass_multi_device(int total_attribute_num)
{
  std::cout << "****test_el_pass_multi_device Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(total_attribute_num, g, gg);

  // IDP-KeyGen
  auto [pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi] = idp.key_gen();

  // User-RequestID
  PSRequester old_dev;
  old_dev.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("s", true));
  attributes.push_back(std::make_tuple("gamma", true));
  attributes.push_back(std::make_tuple("tp", false));
  auto [request_A, request_c, request_rs, request_attributes] = old_dev.el_passo_request_id(attributes, "hello");

  // IDP-ProvideID
  G1 sig1, sig2;
  bool sign_result = idp.el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "hello", sig1, sig2);
  if (!sign_result) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  // User-UnblindID
  auto [ubld_sig1, ubld_sig2] = old_dev.unblind_credential(sig1, sig2);

  // Derive device key to signer2
  auto begin = std::chrono::steady_clock::now();
  auto signer_2 = old_dev.el_passo_derive_device_key("s", "service1");
    auto end = std::chrono::steady_clock::now();
  std::cout << "Old Device: Derive Key: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // New Device
  PSRequester new_dev;
  std::tie(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi) = signer_2->get_pub_key();
  new_dev.init_with_pk(pk_g, pk_gg, pk_XX, pk_Yi, pk_YYi);

  // New Device prepare request
  attributes.clear();
  attributes.push_back(std::make_tuple("secret2", true));
  begin = std::chrono::steady_clock::now();
  std::tie(request_A, request_c, request_rs, request_attributes) = new_dev.el_passo_request_id(attributes, "fordevice");
  end = std::chrono::steady_clock::now();
  std::cout << "New Device: RequestID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // Signer2 signs the request
  begin = std::chrono::steady_clock::now();
  sign_result = signer_2->el_passo_provide_id(request_A, request_c, request_rs, request_attributes, "fordevice", sig1, sig2);
  end = std::chrono::steady_clock::now();
  std::cout << "Old Device: ProvideID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  if (!sign_result) {
    std::cout << "Signer2: sign request failure" << std::endl;
    return;
  }

  // unblind
  begin = std::chrono::steady_clock::now();
  std::tie(ubld_sig1, ubld_sig2) = new_dev.unblind_credential(sig1, sig2);
  end = std::chrono::steady_clock::now();
  std::cout << "New Device: UnblindID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // verify signature
  std::vector<std::string> all_attributes;
  all_attributes.push_back("secret2");
  if (!new_dev.verify(ubld_sig1, ubld_sig2, all_attributes)) {
    std::cout << "New device: unblinded credential verification failure" << std::endl;
    return;
  }

  std::cout << "****test_el_pass_multi_device ends without errors****\n"
            << std::endl;
}

int
main(int argc, char const *argv[])
{
  initPairing();
  test_ps_sign_verify();
  test_el_passo(3);
  test_el_pass_multi_device(3);
}
