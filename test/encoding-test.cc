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

  auto base64Str = buffer.toBase64();
  auto newBuffer = PSBuffer::fromBase64(base64Str);
  if (buffer != newBuffer) {
    std::cout << "test_ps_buffer_encoding base 64 encoding/decoding failure" << std::endl;
      return;
  }
  std::cout << "****test_ps_buffer_encoding without errors****\n" << std::endl;
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
  std::cout << "3 total attributes. Public Key size: " << pubKey.toBufferString().size() << std::endl;

  PSPubKey newKey = PSPubKey::fromBufferString(pubKey.toBufferString());
  if (newKey.g != pubKey.g || newKey.XX != pubKey.XX) {
    std::cout << "test_pk_with_different_attr_num failure" << std::endl;
    return;
  }

  PSSigner idp2(20, g, gg);
  pubKey = idp2.key_gen();
  std::cout << "20 total attributes. Public Key size: " << pubKey.toBufferString().size() << std::endl;
  std::cout << "****test_pk_with_different_attr_num ends without errors****\n"
            << std::endl;
}

void
test_ps_sign_verify()
{
  std::cout << "****test_ps_sign_verify Start****" << std::endl;
  G1 g;
  G2 gg;
  hashAndMapToG1(g, "abc");
  hashAndMapToG2(gg, "edf");
  PSSigner idp(3, g, gg);
  auto pubKey = idp.key_gen();
  pubKey = PSPubKey::fromBufferString(pubKey.toBufferString());

  PSRequester user(pubKey);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("secret1", true));
  attributes.push_back(std::make_tuple("secret2", true));
  attributes.push_back(std::make_tuple("plain1", false));
  auto request = user.el_passo_request_id(attributes, "hello");
  request = PSCredRequest::fromBufferString(request.toBufferString());

  PSCredential sig;
  if (!idp.el_passo_provide_id(request, "hello", sig)) {
    std::cout << "sign request failure" << std::endl;
    return;
  }
  sig = PSCredential::fromBufferString(sig.toBufferString());

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
  auto pk = idp.key_gen();
  auto end = std::chrono::steady_clock::now();
  std::cout << "IDP-KeyGen over " << total_attribute_num << " attributes: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "Public Key Response payload size: " << pk.toBufferString().size() << std::endl;
  std::cout << "Public Key Response base 64 size: " << pk.toBufferString().toBase64().size() << std::endl;

  // User-RequestID
  pk = PSPubKey::fromBufferString(pk.toBufferString());
  PSRequester user(pk);
  std::vector<std::tuple<std::string, bool>> attributes;
  attributes.push_back(std::make_tuple("s", true));
  attributes.push_back(std::make_tuple("gamma", true));
  attributes.push_back(std::make_tuple("tp", false));
  if (total_attribute_num >= 4) {
    attributes.push_back(std::make_tuple("s-new", true));
  }
  begin = std::chrono::steady_clock::now();
  auto request = user.el_passo_request_id(attributes, "hello");
  end = std::chrono::steady_clock::now();
  std::cout << "User-RequestID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "Setup Request payload size: " << request.toBufferString().size() << std::endl;
  std::cout << "Setup Request base 64 size: " << request.toBufferString().toBase64().size() << std::endl;

  // IDP-ProvideID
  request = PSCredRequest::fromBufferString(request.toBufferString());
  PSCredential sig;
  begin = std::chrono::steady_clock::now();
  bool sign_result = idp.el_passo_provide_id(request, "hello", sig);
  end = std::chrono::steady_clock::now();
  std::cout << "IDP-ProvideID: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
            << "[µs]" << std::endl;
  std::cout << "Setup Response payload size: " << sig.toBufferString().size() << std::endl;
  std::cout << "Setup Response base 64 size: " << sig.toBufferString().toBase64().size() << std::endl;
  if (!sign_result) {
    std::cout << "sign request failure" << std::endl;
    return;
  }

  // User-UnblindID
  sig = PSCredential::fromBufferString(sig.toBufferString());
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
  std::cout << "Sign-on Request payload size: " << prove.toBufferString().size() << std::endl;
  std::cout << "Sign-on Request base 64 size: " << prove.toBufferString().toBase64().size() << std::endl;

  // RP-VerifyID
  prove = IdProof::fromBufferString(prove.toBufferString());
  PSVerifier rp(pk);
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
  test_ps_buffer_encoding();
  test_pk_with_different_attr_num();
  test_ps_sign_verify();
  test_el_passo(3);
  test_el_passo(4);
}
