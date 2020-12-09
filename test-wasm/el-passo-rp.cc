#include <emscripten/bind.h>
#include <ps-verifier.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
  class_<PSVerifier>("PSVerifier")
    .constructor<PSPubKey>()
    .function("verify", &PSVerifier::verify)
    .function("el_passo_verify_id", &PSVerifier::el_passo_verify_id)
    .function("el_passo_verify_id_without_id_retrieval", &PSVerifier::el_passo_verify_id_without_id_retrieval);
}