#ifndef PS_SRC_ENCODING_H_
#define PS_SRC_ENCODING_H_

#include <iostream>
#include <vector>
#include <mcl/bls12_381.hpp>
#include <optional>
#include <string>

using namespace mcl::bls12;

enum class PSEncodingType : uint8_t {
  G1 = 1,
  G2 = 2,
  Fr = 3,
  G1List = 4,
  G2List = 5,
  FrList = 6,
  StrList = 7
};

class PSBuffer : public std::vector<uint8_t> {
public:
  void
  appendType(PSEncodingType type);

  size_t
  parseType(size_t offset, PSEncodingType& type) const;

  void
  appendVar(size_t var);

  size_t
  parseVar(size_t offset, size_t& var) const;

  void
  appendG1Element(const G1& g, bool withType = true);

  size_t
  parseG1Element(size_t offset, G1& g, bool withType = true) const;

  void
  appendG2Element(const G2& g, bool withType = true);

  size_t
  parseG2Element(size_t offset, G2& g, bool withType = true) const;

  void
  appendFrElement(const Fr& f, bool withType = true);

  size_t
  parseFrElement(size_t offset, Fr& f, bool withType = true) const;

  void
  appendG1List(const std::vector<G1>& gs);

  size_t
  parseG1List(size_t offset, std::vector<G1>& gs) const;

  void
  appendG2List(const std::vector<G2>& gs);

  size_t
  parseG2List(size_t offset, std::vector<G2>& gs) const;

  void
  appendFrList(const std::vector<Fr>& fs);

  size_t
  parseFrList(size_t offset, std::vector<Fr>& gs) const;

  void
  appendStrList(const std::vector<std::string>& strs);

  size_t
  parseStrList(size_t offset, std::vector<std::string>& strs) const;
};

class PSCredential {
public:
  G1 sig1;
  G1 sig2;

public:
  PSBuffer
  toBufferString();

  static PSCredential
  fromBufferString(const PSBuffer& buf);
};

class PSPubKey {
public:
  G1 g;
  G2 gg;
  G2 XX;
  std::vector<G1> Yi;
  std::vector<G2> YYi;
public:
  PSBuffer
  toBufferString();

  static PSPubKey
  fromBufferString(const PSBuffer& buf);
};

class PSCredRequest {
public:
  G1 A;
  Fr c;
  std::vector<Fr> rs;
  std::vector<std::string> attributes;
public:
  PSBuffer
  toBufferString();

  static PSCredRequest
  fromBufferString(const PSBuffer& buf);
};

class IdProof {
public:
  G1 sig1;
  G1 sig2;
  G2 k;
  G1 phi;
  Fr c;
  std::vector<Fr> rs;
  std::vector<std::string> attributes;
  std::optional<G1> E1;
  std::optional<G1> E2;
public:
  PSBuffer
  toBufferString();

  static IdProof
  fromBufferString(const PSBuffer& buf);
};

#endif // PS_SRC_ENCODING_H_