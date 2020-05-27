#ifndef PS_SRC_PS_REQUESTER_H_
#define PS_SRC_PS_REQUESTER_H_

#include <iostream>
#include <mcl/bls12_381.hpp>
#include <string>

using namespace mcl::bls12;

/**
 * The requester who wants to get a PS credential from the signer.
 */
class PSRequester {
public:
  PSRequester();

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
  void
  init_with_pk(const G1& g, const G2& gg, const G2& XX,
               const std::vector<G1>& Yi, const std::vector<G2>& YYi);

  /**
   * Generate a request along with a NIZK proof for a PSSigner to sign over requester's
   * blinded attributes and plaintext attributes.
   *
   * @p attributes, input, user's attributes in the format of tuple<std::string, bool>.
   *   - std::string, the value of the attribute.
   *   - bool, true if the attribute should be committed.
   * @p associated_data, input, used for NIZK Schnorr verification.
   * @return
   *   - G1, A, committed attributes
   *   - Fr, c, used for NIZK Schnorr verification.
   *   - std::vector<Fr>, rs, used for NIZK Schnorr verification.
   *   - std::vector<std::string>, attributes, attributes that only contain plaintext attributes
   *     and "" for committed attributes. The order of attributes is the same as @p attributes.
   */
  std::tuple<G1, Fr, std::vector<Fr>, std::vector<std::string>>
  el_passo_request_id(const std::vector<std::tuple<std::string, bool>> attributes,  // string is the attribute, bool whether to hide
                      const std::string& associated_data);

  /**
   * Unblind the signature after the PSSigner signs requester's attribtues.
   *
   * @p sig1, the PS signature returned by the PSSigner, part one.
   * @p sig2, the PS signature returned by the PSSigner, part two.
   * @return
   *   - G1, unblinded PS signature, part one.
   *   - G1, unblinded PS signature, part two.
   */
  std::tuple<G1, G1>
  unblind_credential(const G1& sig1, const G1& sig2) const;

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
  verify(const G1& sig1, const G1& sig2, const std::vector<std::string>& all_attributes) const;

  /**
   * Randomize a signature.
   *
   * @p sig1, the PS signature, part one.
   * @p sig2, the PS signature, part two.
   * @return
   *   - G1, randomized PS signature, part one.
   *   - G1, randomized PS signature, part two.
   */
  std::tuple<G1, G1>
  randomize_credential(const G1& sig1, const G1& sig2) const;

  /**
   * EL PASSO ProveID
   * This function will generate:
   *   -# a randomized PS signature (random_sig1, random_sig2).
   *   -# a unique ID (phi) of the user derived from RP's service name and user's primary secret.
   *   -# an identity retrieval token (E1, E2) that can only be decrypted by the authority.
   *   -# an NIZK proof of the PS signature, recovery token, and phi.
   *   -# a list of attributes where the committed attribute slot is "" and plaintext attribute is the full attribute.
   *
   * @p sig1, input, the original PS signature, first part.
   * @p sig2, input, the original PS signature, second part.
   * @p attributes, input, user's attributes in the format of tuple<std::string, bool>.
   *   - std::string, the value of the attribute.
   *   - bool, true if the attribute should be committed.
   * @p associated_data, input, an associated data (e.g., session ID) bound with the NIZK proof used for authentication.
   * @p service_name, input, the RP's service name, e.g., RP's domain name.
   * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority.
   * @p g, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @p h, input, a G1 point that both prover and verifier agree on for NIZK of the identity retrieval token
   * @return
   *   - G1, random_sig1, randomized signature, first part.
   *   - G1, random_sig2, randomized signature, second part.
   *   - G2, k, a part of the public value used for signature verification and NIZK Schnorr verification.
   *   - G1, phi, user's unique ID at RP.
   *   - G1, E1, El Gamal ciphertext as the identity retrieval token, first part.
   *   - G1, E2, El Gamal ciphertext as the identity retrieval token, second part.
   *   - Fr, c, used for NIZK Schnorr verification.
   *   - std::vector<Fr>, rs, used for NIZK Schnorr verification.
   *   - std::vector<std::string>, attributes, attributes that only contain plaintext attributes
   *     and "" for committed attributes. The order of attributes is the same as @p attributes.
   */
  std::tuple<G1, G1, G2, G1, G1, G1, Fr, std::vector<Fr>, std::vector<std::string>>  // sig1, sig2, k, phi, E1, E2, c, rs, attributes
  el_passo_prove_id(const G1& sig1, const G1& sig2,
                    const std::vector<std::tuple<std::string, bool>> attributes,
                    const std::string& associated_data,
                    const std::string& service_name,
                    const G1& authority_pk, const G1& g, const G1& h);


  std::tuple<G1, G1, G2, G1, Fr, std::vector<Fr>, std::vector<std::string>>  // sig1, sig2, k, phi, c, rs, attributes
  el_passo_prove_id_without_id_retrieval(const G1& sig1, const G1& sig2,
                                         const std::vector<std::tuple<std::string, bool>> attributes,
                                         const std::string& associated_data,
                                         const std::string& service_name);

private:
  G2
  prepare_hybrid_verification(const G2& k, const std::vector<std::string>& attributes) const;

private:
  G1 m_g;                    // G1 generator
  G2 m_gg;                   // G2 generator
  Fr m_sk_x;                 // private key, x
  G1 m_sk_X;                 // private key, X
  G2 m_pk_XX;                // public key, XX
  std::vector<G1> m_pk_Yi;   // public key, yi
  std::vector<G2> m_pk_YYi;  // public key, yyi
  Fr m_t1;                   // used for commiting attributes
};

#endif  // PS_SRC_PS_REQUESTER_H_