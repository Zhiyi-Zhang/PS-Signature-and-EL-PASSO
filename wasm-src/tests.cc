#include <emscripten/emscripten.h>
#include <ps-encoding.h>
#include <ps-requester.h>
#include <ps-signer.h>
#include <ps-verifier.h>

#include <iostream>

using namespace mcl::bls12;

void
test_el_passo(size_t total_attribute_num)
{
  std::cout << "****test_el_passo Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(total_attribute_num);

  // IDP-KeyGen
  auto begin = std::chrono::steady_clock::now();
  auto pk = idp.key_gen();
  auto end = std::chrono::steady_clock::now();
  std::cout << "IDP-KeyGen over " << total_attribute_num << " attributes: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "PK Base64: " << pk.toBufferString().toBase64() << std::endl;

  // User-RequestID
  PSRequester user(pk);
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
  std::cout << "RequestID Base64: " << request.toBufferString().toBase64() << std::endl;

  // IDP-ProvideIDs
  PSCredential sig;
  begin = std::chrono::steady_clock::now();
  bool sign_result = idp.el_passo_provide_id(request, "hello", sig);
  end = std::chrono::steady_clock::now();
  std::cout << "IDP-ProvideID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "Credential Base64: " << sig.toBufferString().toBase64() << std::endl;
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
  auto prove_id = user.el_passo_prove_id(ubld_sig, attributes, "hello", "service", authority_pk, g, h);
  end = std::chrono::steady_clock::now();
  std::cout << "User-ProveID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "ProveID Base64: " << prove_id.toBufferString().toBase64() << std::endl;

  // RP-VerifyID
  PSVerifier rp(pk);
  begin = std::chrono::steady_clock::now();
  bool result = rp.el_passo_verify_id(prove_id, "hello", "service", authority_pk, g, h);
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

#ifdef __cplusplus
extern "C" {
#endif

void EMSCRIPTEN_KEEPALIVE
run_tests()
{
  initPairing();
  test_el_passo(3);
}

#ifdef __cplusplus
}
#endif
