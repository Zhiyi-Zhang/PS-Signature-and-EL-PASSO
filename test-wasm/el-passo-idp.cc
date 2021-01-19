#include <emscripten/bind.h>
#include <ps-signer.h>

using namespace emscripten;
using namespace mcl::bls12;

void initPS() {
  initPairing();
}

std::string
el_passo_prove_id(PSSigner& signer, const std::string& requestStr, const std::string& assoData)
{
  auto request = PSCredRequest::fromBufferString(PSBuffer::fromBase64(requestStr));
  PSCredential credential;
  auto success = signer.el_passo_provide_id(request, assoData, credential);
  if (!success) {
    return "";
  }
  else {
    return credential.toBufferString().toBase64();
  }
}

EMSCRIPTEN_BINDINGS(my_module) {
  function("initPairing", &initPS);
  function("el_passo_prove_id", &el_passo_prove_id);

  class_<PSBuffer>("PSBuffer")
    .class_function("fromBase64", &PSBuffer::fromBase64)
    .function("toBase64", &PSBuffer::toBase64);

  class_<PSCredential>("PSCredential")
    .function("toBufferString", &PSCredential::toBufferString)
    .class_function("fromBufferString", &PSCredential::fromBufferString);

  class_<PSPubKey>("PSPubKey")
    .function("toBufferString", &PSPubKey::toBufferString)
    .class_function("fromBufferString", &PSPubKey::fromBufferString);

  class_<PSCredRequest>("PSCredRequest")
    .function("toBufferString", &PSCredRequest::toBufferString)
    .class_function("fromBufferString", &PSCredRequest::fromBufferString);

  class_<IdProof>("IdProof")
    .function("toBufferString", &IdProof::toBufferString)
    .class_function("fromBufferString", &IdProof::fromBufferString);

  class_<PSSigner>("PSSigner")
    .constructor<int>()
    .function("key_gen", &PSSigner::key_gen)
    .function("get_pub_key", &PSSigner::get_pub_key)
    .function("el_passo_provide_id", &PSSigner::el_passo_provide_id);
}