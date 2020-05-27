#include <emscripten/bind.h>
#include <ps-signer.h>
#include <ps-requester.h>
#include <ps-verifier.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
  class_<PSSigner>("PSSigner")
    .constructor<int>()
    .function("key_gen", &PSSigner::key_gen)
    .function("get_pub_key", &PSSigner::get_pub_key)
    .function("el_passo_provide_id", &PSSigner::el_passo_provide_id)
    .function("sign_commitment", &PSSigner::sign_commitment)
    .function("sign_hybrid", &PSSigner::sign_hybrid);

  class_<PSRequester>("PSRequester")
    .constructor<>()
    .function("init_with_pk", &PSRequester::init_with_pk)
    .function("el_passo_request_id", &PSRequester::el_passo_request_id)
    .function("unblind_credential", &PSRequester::unblind_credential)
    .function("verify", &PSRequester::verify)
    .function("randomize_credential", &PSRequester::randomize_credential)
    .function("el_passo_prove_id", &PSRequester::el_passo_prove_id)
    .function("el_passo_prove_id_without_id_retrieval", &PSRequester::el_passo_prove_id_without_id_retrieval);

  class_<PSVerifier>("PSVerifier")
    .constructor<>()
    .function("init_with_pk", &PSVerifier::init_with_pk)
    .function("verify", &PSVerifier::verify)
    .function("el_passo_verify_id", &PSVerifier::el_passo_verify_id)
    .function("el_passo_verify_id_without_id_retrieval", &PSVerifier::el_passo_verify_id_without_id_retrieval);
}