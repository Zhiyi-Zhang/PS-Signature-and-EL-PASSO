#include <nizk-schnorr.h>
#include <iostream>

using namespace mcl::bls12;

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

int main(int argc, char const *argv[])
{
  initPairing();
  test_nizk_schnorr();
}