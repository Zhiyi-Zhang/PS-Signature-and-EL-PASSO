#include <emscripten/bind.h>
#include <ps-requester.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
  class_<PSRequester>("PSRequester")
    .constructor<>()
    .function("init_with_pk", &PSRequester::init_with_pk)
    .function("el_passo_request_id", &PSRequester::el_passo_request_id)
    .function("unblind_credential", &PSRequester::unblind_credential)
    .function("verify", &PSRequester::verify)
    .function("randomize_credential", &PSRequester::randomize_credential)
    .function("el_passo_prove_id", &PSRequester::el_passo_prove_id)
    .function("el_passo_prove_id_without_id_retrieval", &PSRequester::el_passo_prove_id_without_id_retrieval);
}