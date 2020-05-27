#include <emscripten/bind.h>
#include <ps-verifier.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
  class_<PSVerifier>("PSVerifier")
    .constructor<>()
    .function("init_with_pk", &PSVerifier::init_with_pk)
    .function("verify", &PSVerifier::verify)
    .function("el_passo_verify_id", &PSVerifier::el_passo_verify_id)
    .function("el_passo_verify_id_without_id_retrieval", &PSVerifier::el_passo_verify_id_without_id_retrieval);
}