#include <ps.h>
#include <nizk-schnorr.h>
#include <iostream>

using namespace mcl::bls12;

void
test_key_gen()
{
  std::cout << "****test_key_gen Start****" << std::endl;
  PSSigner signer;
  auto pk = signer.key_gen(2);
  // std::cout << pk->SerializeAsString().size() << std::endl;
  // std::cout << pk->DebugString() << std::endl;
  pk = signer.key_gen(4);
  // std::cout << pk->SerializeAsString().size() << std::endl;
  // std::cout << pk->DebugString() << std::endl;

  std::string encoded_pk = pk->SerializeAsString();
  PSPubKey pk2;
  if (!pk2.ParseFromString(encoded_pk)) {
    std::cout << "Cannot decode pk correctly" << std::endl;
    return;
  }
  std::cout << "****test_key_gen ends without errors****\n" << std::endl;
}

void
test_cred_application()
{
  std::cout << "****test_cred_application Start****" << std::endl;
  PSSigner idp;
  auto pk = idp.key_gen(3);

  PSRequester user(pk);
  std::list<std::string> c_attributes;
  c_attributes.push_back("secret1");
  c_attributes.push_back("secret2");
  std::list<std::string> attributes;
  attributes.push_back("plain1");
  auto request = user.generate_request(c_attributes, attributes);
  // std::cout << request->SerializeAsString().size() << std::endl;
  // std::cout << request->DebugString() << std::endl;

  auto cred1 = idp.sign_cred_request(*request);
  if (cred1 == nullptr) {
    std::cout << "sign request failure" << std::endl;
  }

  auto cred2 = user.unblind_credential(*cred1);
  std::list<std::string> all_attributes;
  all_attributes.push_back("secret1");
  all_attributes.push_back("secret2");
  all_attributes.push_back("plain1");
  if (!user.verify(*cred2, all_attributes)) {
    std::cout << "verification unblinded credential failure" << std::endl;
    return;
  }

  auto cred3 = user.randomize_credential(*cred2);
  if (!user.verify(*cred3, all_attributes)) {
    std::cout << "verification randomized credential failure" << std::endl;
    return;
  }
  std::cout << "****test_cred_application ends without errors****\n" << std::endl;
}

void
test_nizk_schnorr()
{
  std::cout << "****test_nizk_schnorr Start****" << std::endl;
  // prepare
  G1 g;
  Fr secret;
  hashAndMapToG1(g, "abc", 3);
  secret.setByCSPRNG();
  // test
  G1 A, V;
  Fr r;
  nizk_schnorr_prove(g, secret, "hello", A, V, r);
  bool result = nizk_schnorr_verify(g, A, V, r, "hello");
  if (!result) {
    std::cout << "NIZK schnorr failure" << std::endl;
    return;
  }
  std::cout << "****test_nizk_schnorr ends without errors****\n" << std::endl;
}

void
test_zk_sig_prove()
{
  std::cout << "****test_zk_sig_prove Start****" << std::endl;
  PSSigner idp;
  auto pk = idp.key_gen(3);

  PSRequester user(pk);
  std::list<std::string> c_attributes;
  c_attributes.push_back("secret1");
  c_attributes.push_back("secret2");
  std::list<std::string> attributes;
  attributes.push_back("plain1");
  auto request = user.generate_request(c_attributes, attributes);

  auto cred1 = idp.sign_cred_request(*request);
  if (cred1 == nullptr) {
    std::cout << "sign request failure" << std::endl;
  }

  auto cred2 = user.unblind_credential(*cred1);
  std::list<std::string> all_attributes;
  all_attributes.push_back("secret1");
  all_attributes.push_back("secret2");
  all_attributes.push_back("plain1");
  if (!user.verify(*cred2, all_attributes)) {
    std::cout << "verification unblinded credential failure" << std::endl;
    return;
  }

  auto [cred3, proof]  = user.zk_prove_credentail(*cred2, c_attributes, attributes, "abc");

  PSRequester user2(pk);
  if (!user2.zk_verify_credential(*cred3, *proof, "abc")) {
    std::cout << "zk proof failure" << std::endl;
    return;
  }
  std::cout << "****test_zk_sig_prove ends without errors****\n" << std::endl;
}

int main(int argc, char const *argv[])
{
  initPairing();
  test_key_gen();
  test_nizk_schnorr();
  test_cred_application();
  test_zk_sig_prove();
}
