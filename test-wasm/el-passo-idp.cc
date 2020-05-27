#include <emscripten/bind.h>
#include <ps-signer.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
  class_<PSSigner>("PSSigner")
    .constructor<int>()
    .function("key_gen", &PSSigner::key_gen)
    .function("get_pub_key", &PSSigner::get_pub_key)
    .function("el_passo_provide_id", &PSSigner::el_passo_provide_id)
    .function("sign_commitment", &PSSigner::sign_commitment)
    .function("sign_hybrid", &PSSigner::sign_hybrid);
}