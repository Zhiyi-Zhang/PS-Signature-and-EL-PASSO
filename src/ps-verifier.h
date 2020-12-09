#ifndef PS_SRC_PS_VERIFIER_H_
#define PS_SRC_PS_VERIFIER_H_

#include "ps-encoding.h"

using namespace mcl::bls12;

/**
 * The verifier who wants to verify a user's ownership of a PS credential.
 */
class PSVerifier {
public:
  /**
   * Add PS public key.
   * This function should be called before any other PS related functions.
   *
   * @p g, input, generator of G1.
   * @p gg, input, generator of G2.
   * @p XX, input, gg^x, a point in G2.
   * @p Yi, input, g^yi, points in G1. Yi.size() is the fixed based on PS public key's allowed attribute size.
   * @p YYi, input, gg^yi, points in G2. Yi.size() is the fixed based on PS public key's allowed attribute size.
   */
  PSVerifier(const PSPubKey& pk);

  /**
   * Verify the signature over the given attributes (all in plaintext).
   *
   * @p sig1, the PS signature, part one.
   * @p sig2, the PS signature, part two.
   * @p all_attributes, the attributes in the same order as when the PS signature is requested.
   *                    All in plaintext.
   * @return true if the signature is valid.
   */
  bool
  verify(const PSCredential& sig, const std::vector<std::string>& all_attributes) const;

  /**
   * EL PASSO VerifyID
   * This function will:
   *  -# verify the NIZK proof of the PS signature, ID recovery token, and Phi.
   *  -# verify the PS signature over the committed attributes and the plaintext attributes.
   *
   * @p sig1, input, the randomized PS signature, first part.
   * @p sig2, input, the randomized PS signature, second part.
   * @p k, input, used for signature verification and NIZK Schnorr verification.
   * @p phi, input, user's unique ID at RP.
   * @p E1, input, El Gamal ciphertext as the identity retrieval token, first part.
   * @p E2, input, El Gamal ciphertext as the identity retrieval token, second part.
   * @p c, input, used for NIZK Schnorr verification.
   * @p rs, input, used for NIZK Schnorr verification.
   * @p attributes, input, user's attributes including
   *   - "" represents those committed attributes.
   *   - normal plaintext attributes.
   * @p associated_data, input, an associated data (e.g., session ID) bound with the NIZK proof used for authentication.
   * @p service_name, input, the RP's service name, e.g., RP's domain name.
   * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority.
   * @p g, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @p h, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @return true if both the NIZK proof and signature are valid.
   */
  bool
  el_passo_verify_id(const G1& sig1, const G1& sig2, const G2& k, const G1& phi,
                     const G1& E1, const G1& E2, const Fr& c,
                     const std::vector<Fr>& rs, const std::vector<std::string>& attributes,
                     const std::string& associated_data,
                     const std::string& service_name,
                     const G1& authority_pk, const G1& g, const G1& h);

  bool
  el_passo_verify_id_without_id_retrieval(const G1& sig1, const G1& sig2, const G2& k, const G1& phi,
                                          const Fr& c, const std::vector<Fr>& rs,
                                          const std::vector<std::string>& attributes,
                                          const std::string& associated_data, const std::string& service_name);

private:
  G2
  prepare_hybrid_verification(const G2& k, const std::vector<std::string>& attributes) const;

private:
  PSPubKey m_pk;  // public key
  Fr m_sk_x;      // private key, x
  G1 m_sk_X;      // private key, X
  Fr m_t1;        // used for commiting attributes
};

#endif  // PS_SRC_PS_VERIFIER_H_