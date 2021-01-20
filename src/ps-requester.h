#ifndef PS_SRC_PS_REQUESTER_H_
#define PS_SRC_PS_REQUESTER_H_

#include "ps-encoding.h"

using namespace mcl::bls12;

/**
 * The requester who wants to get a PS credential from the signer.
 */
class PSRequester {
public:
  /**
   * @brief Construct a new PSRequester object
   *
   * @param pk input The public key of the PSSigner.
   */
  PSRequester(const PSPubKey& pk);

  size_t
  maxAllowedAttrNum() const;

  /**
   * @brief Generate a request along with a NIZK proof for the PSSigner to sign over requester's
   *        blinded attributes and plaintext attributes.
   *
   * @p attributes, input, user's attributes in the format of tuple<std::string, bool>.
   *   - std::string, the value of the attribute.
   *   - bool, true if the attribute should be committed.
   * @p associated_data, input, used for NIZK Schnorr verification.
   * @return PSCredRequest containing
   *   - G1, A, committed attributes
   *   - Fr, c, used for NIZK Schnorr verification.
   *   - std::vector<Fr>, rs, used for NIZK Schnorr verification.
   *   - std::vector<std::string>, attributes, attributes that only contain plaintext attributes
   *     and "" for committed attributes. The order of attributes is the same as @p attributes.
   */
  PSCredRequest
  el_passo_request_id(const std::vector<std::tuple<std::string, bool>> attributes,  // string is the attribute, bool whether to hide
                      const std::string& associated_data);

  /**
   * Unblind the signature after the PSSigner signs requester's attribtues.
   *
   * @p sig, the PS signature (certificate) returned by the PSSigner.
   * @return PSCredential containing
   *   - G1, unblinded PS signature, part one.
   *   - G1, unblinded PS signature, part two.
   */
  PSCredential
  unblind_credential(const PSCredential& sig) const;

  /**
   * Verify the signature over the given attributes (all in plaintext).
   *
   * @p sig, the PS signature.
   * @p all_attributes, the attributes in the same order as when the PS signature is requested.
   *                    All in plaintext.
   * @return true if the signature is valid.
   */
  bool
  verify(const PSCredential& sig, const std::vector<std::string>& all_attributes) const;

  /**
   * Randomize a signature.
   *
   * @p sig, the PS signature.
   * @return PSCredential containing
   *   - G1, randomized PS signature, part one.
   *   - G1, randomized PS signature, part two.
   */
  PSCredential
  randomize_credential(const PSCredential& sig) const;

  /**
   * EL PASSO ProveID
   * This function will generate:
   *   -# a randomized PS signature (random_sig1, random_sig2).
   *   -# a unique ID (phi) of the user derived from RP's service name and user's primary secret.
   *   -# an identity retrieval token (E1, E2) that can only be decrypted by the authority.
   *   -# an NIZK proof of the PS signature, recovery token, and phi.
   *   -# a list of attributes where the committed attribute slot is "" and plaintext attribute is the full attribute.
   *
   * @p sig, input, the original PS signature.
   * @p attributes, input, user's attributes in the format of tuple<std::string, bool>.
   *   - std::string, the value of the attribute.
   *   - bool, true if the attribute should be committed.
   * @p associated_data, input, an associated data (e.g., session ID) bound with the NIZK proof used for authentication.
   * @p service_name, input, the RP's service name, e.g., RP's domain name.
   * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority.
   * @p g, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @p h, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @return IdProof containing
   *   - G1, random_sig1, randomized signature, first part.
   *   - G1, random_sig2, randomized signature, second part.
   *   - G2, k, a part of the public value used for signature verification and NIZK Schnorr verification.
   *   - G1, phi, user's unique ID at RP.
   *   - Fr, c, used for NIZK Schnorr verification.
   *   - std::vector<Fr>, rs, used for NIZK Schnorr verification.
   *   - std::vector<std::string>, attributes, attributes that only contain plaintext attributes
   *     and "" for committed attributes. The order of attributes is the same as @p attributes.
   *  When id retrieval is enabled, two addition elements are included:
   *   - G1, E1, El Gamal ciphertext as the identity retrieval token, first part.
   *   - G1, E2, El Gamal ciphertext as the identity retrieval token, second part.
   */
  IdProof
  el_passo_prove_id(const PSCredential& sig,
                    const std::vector<std::tuple<std::string, bool>> attributes,
                    const std::string& associated_data,
                    const std::string& service_name,
                    const G1& authority_pk, const G1& g, const G1& h) const;

  IdProof
  el_passo_prove_id_without_id_retrieval(const PSCredential& sig,
                                         const std::vector<std::tuple<std::string, bool>> attributes,
                                         const std::string& associated_data,
                                         const std::string& service_name) const;

private:
  G2
  prepare_hybrid_verification(const G2& k, const std::vector<std::string>& attributes) const;

private:
  PSPubKey m_pk;  // public key
  Fr m_sk_x;      // private key, x
  G1 m_sk_X;      // private key, X
  Fr m_t1;        // used for commiting attributes
};

#endif  // PS_SRC_PS_REQUESTER_H_