#include <ps-requester.h>
#include <ps-signer.h>
#include <ps-verifier.h>

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
  PSPubKey pubKey = idp.key_gen();

  PSRequester user(pubKey);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("secret1", true));
  attributes.push_back(std::make_tuple("secret2", true));
  attributes.push_back(std::make_tuple("plain1", false));
  auto request = user.el_passo_request_id(attributes, "hello");

  PSCredential sig;
  if (!idp.el_passo_provide_id(request, "hello", sig)) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  auto ubld_sig = user.unblind_credential(sig);
  std::vector<std::string> all_attributes;
  all_attributes.push_back("secret1");
  all_attributes.push_back("secret2");
  all_attributes.push_back("plain1");
  if (!user.verify(ubld_sig, all_attributes)) {
    std::cout << "unblinded credential verification failure" << std::endl;
    return;
  }

  auto rand_sig = user.randomize_credential(ubld_sig);
  if (!user.verify(rand_sig, all_attributes)) {
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
  auto pubKey = idp.key_gen();
  auto end = std::chrono::steady_clock::now();
  std::cout << "IDP-KeyGen over " << total_attribute_num << " attributes: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // User-RequestID
  PSRequester user(pubKey);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("s", true));
  attributes.push_back(std::make_tuple("gamma", true));
  attributes.push_back(std::make_tuple("tp", false));
  begin = std::chrono::steady_clock::now();
  auto request = user.el_passo_request_id(attributes, "hello");
  end = std::chrono::steady_clock::now();
  std::cout << "User-RequestID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // IDP-ProvideID
  PSCredential sig;
  begin = std::chrono::steady_clock::now();
  bool sign_result = idp.el_passo_provide_id(request, "hello", sig);
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
  auto ubld_sig = user.unblind_credential(sig);
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
  auto prove = user.el_passo_prove_id(ubld_sig, attributes, "hello", "service", authority_pk, g, h);
  end = std::chrono::steady_clock::now();
  std::cout << "User-ProveID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;

  // RP-VerifyID
  PSVerifier rp(pubKey);
  begin = std::chrono::steady_clock::now();
  bool result = rp.el_passo_verify_id(prove, "hello", "service", authority_pk, g, h);
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

int
main(int argc, char const *argv[])
{
  initPairing();
  test_ps_sign_verify();
  test_el_passo(3);
}
