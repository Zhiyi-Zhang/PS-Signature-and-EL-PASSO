#include <emscripten/bind.h>
#include <ps-verifier.h>

using namespace emscripten;
using namespace mcl::bls12;

// a function that should be called before any other exported functions
void initPS() {
  initPairing();
}

EMSCRIPTEN_BINDINGS(my_module) {
  function("initPairing", &initPS);

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

  class_<PSVerifier>("PSVerifier")
    .constructor<PSPubKey>()
    .function("verify", &PSVerifier::verify)
    .function("el_passo_verify_id", &PSVerifier::el_passo_verify_id)
    .function("el_passo_verify_id_without_id_retrieval", &PSVerifier::el_passo_verify_id_without_id_retrieval)
    .class_function("get_user_name_from_signon_request", &PSVerifier::get_user_name_from_signon_request);
}