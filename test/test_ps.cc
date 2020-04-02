#include <ps.h>
#include <nizk-schnorr.h>
#include <iostream>

using namespace mcl::bls12;

void
test_key_gen()
{
  PSSigner ps;
  auto pk = ps.key_gen(2);
  std::cout << pk->SerializeAsString().size() << std::endl;
  std::cout << pk->DebugString() << std::endl;
  pk = ps.key_gen(4);
  std::cout << pk->SerializeAsString().size() << std::endl;
  std::cout << pk->DebugString() << std::endl;
}

void
test_cred_application()
{
  PSSigner idp;
  auto pk = idp.key_gen(2);

  PSRequester user(pk);
  std::list<std::string> c_attributes;
  c_attributes.push_back("secret1");
  c_attributes.push_back("secret2");
  std::list<std::string> attributes;
  attributes.push_back("plain1");
  auto request = user.generate_request(c_attributes, attributes);
  std::cout << request->SerializeAsString().size() << std::endl;
  std::cout << request->DebugString() << std::endl;
}

void
test_nizk_schnorr()
{
  initPairing();
  // prepare
  G1 g;
  Fp secret;
  hashAndMapToG1(g, "abc", 3);
  secret.setRand();
  // test
  G1 A, V;
  Fp r;
  nizk_schnorr_prove(g, secret, "hello world", A, V, r);
  bool result = nizk_schnorr_verify(g, A, V, r, "hello world");
  std::cout << result  << std::endl;
}

int main(int argc, char const *argv[])
{
  test_nizk_schnorr();
  // test_cred_application();
}
