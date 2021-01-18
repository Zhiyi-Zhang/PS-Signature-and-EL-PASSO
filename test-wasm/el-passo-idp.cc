#include <emscripten/bind.h>
#include <ps-signer.h>

using namespace emscripten;
using namespace mcl::bls12;

void initPS() {
  initPairing();
}

// // a wrapper class of PSSigner to use builtin data types
// class PassoIdP : public PSSigner {
//   public:
//   PassoIdP(size_t num);

//   std::string
//   getPubKey() const;

//   std::string
//   proveId(const std::string& request, const std::string& assData) const;
// };

// PassoIdP::PassoIdP(size_t num)
//   : PSSigner(num)
// {}

// std::string
// PassoIdP::getPubKey() const
// {
//   auto pk = this->get_pub_key();
//   return pk.toBufferString().toBase64();
// }

// std::string
// PassoIdP::proveId(const std::string& requestStr, const std::string& assData) const
// {
//   auto request = PSCredRequest::fromBufferString(PSBuffer::fromBase64(requestStr));
//   PSCredential credential;
//   auto success = this->el_passo_provide_id(request, assData, credential);
//   if (!success) {
//     return "";
//   }
//   else {
//     return credential.toBufferString().toBase64();
//   }
// }

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

  class_<PSSigner>("PSSigner")
    .constructor<int>()
    .function("key_gen", &PSSigner::key_gen)
    .function("get_pub_key", &PSSigner::get_pub_key)
    .function("el_passo_provide_id", &PSSigner::el_passo_provide_id);
}