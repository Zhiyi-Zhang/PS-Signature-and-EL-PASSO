#include <emscripten/bind.h>
#include <ps-requester.h>
#include <sstream>
#include <iterator>

using namespace emscripten;
using namespace mcl::bls12;

void initPS() {
  initPairing();
}

template <typename Out>
void split(const std::string &s, char delim, Out result) {
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

// format: att1 Y att2 N att3 Y
std::vector<std::tuple<std::string, bool>>
string2AttributeVector(const std::string& vectorStr) {
  std::vector<std::string> elems;
  split(vectorStr, ' ', std::back_inserter(elems));
  std::vector<std::tuple<std::string, bool>> result;
  for (size_t i = 0; i < elems.size();) {
    const auto& value = elems[i];
    const auto& hideSign = elems[i + 1];
    bool hide = false;
    if (hideSign == "Y") {
      hide = true;
    }
    result.push_back(std::make_tuple(value, hide));
    i += 2;
  }
  return result;
}

EMSCRIPTEN_BINDINGS(my_module) {
  function("initPairing", &initPS);
  function("string2AttributeVector", &string2AttributeVector);

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

  class_<PSRequester>("PSRequester")
    .constructor<PSPubKey>()
    .function("maxAllowedAttrNum", &PSRequester::maxAllowedAttrNum)
    .function("el_passo_request_id", &PSRequester::el_passo_request_id)
    .function("unblind_credential", &PSRequester::unblind_credential)
    .function("verify", &PSRequester::verify)
    .function("randomize_credential", &PSRequester::randomize_credential)
    .function("el_passo_prove_id", &PSRequester::el_passo_prove_id)
    .function("el_passo_prove_id_without_id_retrieval", &PSRequester::el_passo_prove_id_without_id_retrieval);
}