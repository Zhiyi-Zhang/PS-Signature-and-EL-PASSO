#ifndef PS_SRC_ENCODING_H_
#define PS_SRC_ENCODING_H_

#include <iostream>
#include <mcl/bls12_381.hpp>
#include <optional>
#include <string>
#include <vector>

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
public:  // used for base64 encoding and decoding
  static PSBuffer
  fromBase64(const std::string& base64Str);

  std::string
  toBase64();

public:  // used for TLV encoding and decoding
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

/**
 * @brief A PS Signature. Used as credential/certificate in EL PASSO.
 */
class PSCredential {
public:
  /**
   * @brief The part one of the signature.
   */
  G1 sig1;
  /**
   * @brief The part one of the signature.
   */
  G1 sig2;

public:
  PSBuffer
  toBufferString();

  static PSCredential
  fromBufferString(const PSBuffer& buf);
};

/**
 * @brief Public key used in PS Signature and EL PASSO.
 */
class PSPubKey {
public:
  /**
   * @brief Generator of group G1.
   */
  G1 g;
  /**
   * @brief Generator of group G2.
   */
  G2 gg;
  /**
   * @brief gg^x, a point in G2.
   */
  G2 XX;
  /**
   * @brief g^yi, points in G1. Yi.size() is fixed based on PS public key's allowed attribute size.
   */
  std::vector<G1> Yi;
  /**
   * @brief gg^yi, points in G2. YYi.size() is fixed based on PS public key's allowed attribute size.
   */
  std::vector<G2> YYi;

public:
  PSBuffer
  toBufferString();

  static PSPubKey
  fromBufferString(const PSBuffer& buf);
};

/**
 * @brief Certificate request for a PSRequester to get a certificate from the PSSigner.
 */
class PSCredRequest {
public:
  /**
   * @brief A G1 point to which all hidden attributes (secrets) are committed.
   */
  G1 A;
  /**
   * @brief Used for NIZK Schnorr verification.
   */
  Fr c;
  /**
   * @brief Used for NIZK Schnorr verification.
   */
  std::vector<Fr> rs;
  /**
   * @brief A list of plaintext attributes. Empty strings are placeholders for committed attributes.
   */
  std::vector<std::string> attributes;

public:
  PSBuffer
  toBufferString();

  static PSCredRequest
  fromBufferString(const PSBuffer& buf);
};

/**
 * @brief PSRequester's certificate, attributes, unique ID at RP, ID recovery token and corresponding proofs.
 */
class IdProof {
public:
  /**
   * @brief Randomized signature, first part.
   */
  G1 sig1;
  /**
   * @brief Randomized signature, first part.
   */
  G1 sig2;
  /**
   * @brief A public value used for signature verification and NIZK Schnorr verification.
   */
  G2 k;
  /**
   * @brief PSRequester's unique ID at RP.
   */
  G1 phi;
  /**
   * @brief used for NIZK Schnorr verification.
   */
  Fr c;
  /**
   * @brief used for NIZK Schnorr verification.
   */
  std::vector<Fr> rs;
  /**
   * @brief A list of plaintext attributes. Empty strings are placeholders for committed attributes.
   */
  std::vector<std::string> attributes;
  /**
   * @brief El Gamal ciphertext as the identity retrieval token, first part.
   */
  std::optional<G1> E1;
  /**
   * @brief El Gamal ciphertext as the identity retrieval token, first part.
   */
  std::optional<G1> E2;

public:
  PSBuffer
  toBufferString();

  static IdProof
  fromBufferString(const PSBuffer& buf);
};

#endif  // PS_SRC_ENCODING_H_