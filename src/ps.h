#ifndef PS_SRC_PS_H_
#define PS_SRC_PS_H_

#include "ps.pb.h"
#include <string>
#include <iostream>
#include <list>
#include <mcl/bls12_381.hpp>
#include <cybozu/sha2.hpp>

using namespace mcl::bls12;

// In this PS implementation, the commitmented attributes goes first and plaintext attribtues goes after
// Prerequisite: initPairing();

class PSSigner
{
public:
  typedef std::unique_ptr<PSSigner> Ptr;

  PSSigner();

  // will update private member variables
  std::shared_ptr<PSPubKey>
  key_gen(int attribute_num);

  // if schnorr protocol fails, a nullptr will be returned
  std::shared_ptr<PSCredential>
  sign_cred_request(const PSCredRequest& request) const;

  std::shared_ptr<PSCredential>
  sign_hybrid(const G1& gt, const std::list<G1>& c_attributes, const std::list<std::string>& attributes) const;

  std::shared_ptr<PSCredential>
  sign_commitment(const G1& commitment) const;

private:
  G1 m_g;
	G2 m_gg;
  Fr m_x; // sk1
  G1 m_X; // sk2
  std::shared_ptr<PSPubKey> m_pk;
};

class PSRequester
{
public:
  typedef std::unique_ptr<PSRequester> Ptr;

  PSRequester(const std::shared_ptr<PSPubKey>& pk);

  std::shared_ptr<PSCredRequest>
  generate_request(const std::list<std::string> attributes_to_commitment,
                   const std::list<std::string> plaintext_attributes);

  std::shared_ptr<PSCredential>
  unblind_credential(const PSCredential& credential) const;

  bool
  verify(const PSCredential& credential, const std::list<std::string>& attributes) const;

  std::shared_ptr<PSCredential>
  randomize_credential(const PSCredential& credential);

  /**
   * Generate NIZK proof of the credential.
   * To simplify the implementation, @p attributes_to_commitment concatenated with @p plaintext_attributes
   * must be equal to attributes parameter used in PSRequester::verify (the order of attributes matters).
   * Therefore, a PSRequester should divide all attributes into two sub lists (order won't change), where
   * the first @p attributes_to_commitment.size() attributes will be hidden from the credential verifier.
   *
   * @p credential, input, the PS signature to prove
   * @p attributes_to_commitment, input, the attributes to hide from the verifier
   * @p plaintext_attributes, input, the attribtues to disclose to the verifier
   * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
   * @return a tuple of the randomized credential and the proof of the credential
   */
  std::tuple<std::shared_ptr<PSCredential>, std::shared_ptr<PSCredProof>>
  zk_prove_credentail(const PSCredential& credential,
                      const std::list<std::string> attributes_to_commitment,
                      const std::list<std::string> plaintext_attributes,
                      const std::string& associated_data);

  /**
   * Verify the NIZK proof of the credential.
   *
   * @p credential, input, a randomized PS signature
   * @p proof, input, the NIZK proof of the PS signature
   * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
   * @return true if verification succeeds; otherwise, return false
   */
  bool
  zk_verify_credential(const PSCredential& credential, const PSCredProof& proof,
                       const std::string& associated_data);

  /**
   * Generate NIZK proof of the credential and a identity recovery token.
   * Only the accountabilty authority can recover prover's identity from the identity recovery token.
   *
   * @p credential, input, the PS signature to prove
   * @p attributes_to_commitment, input, the attributes to hide from the verifier
   * @p plaintext_attributes, input, the attribtues to disclose to the verifier
   * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
   * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority
   * @p identity_attribute, input, the identity attribute to hide in the identity recovery token, must be a attribute in @p attributes_to_commitment
   * @p g, input, a G1 point that both prover and verifier agree on for NIZK of the identity recovery token
   * @p h, input, a G1 point that both prover and verifier agree on for NIZK of the identity recovery token
   * @return a tuple of the randomized credential, the proof of the credential, and an identity recovery secret with its proof
   */
  std::tuple<std::shared_ptr<PSCredential>, std::shared_ptr<PSCredProof>, std::shared_ptr<IdRecoveryToken>>
  zk_prove_credentail_with_accountability(const PSCredential& credential,
                                          const std::list<std::string> attributes_to_commitment,
                                          const std::list<std::string> plaintext_attributes,
                                          const std::string& associated_data, const G1Point& authority_pk,
                                          const std::string& identity_attribute, const G1& g, const G1& h);

  /**
   * Verify the NIZK proof of the credential and the identity recovery token is correctly generated.
   * This function only verify the @p id_recovery_token is correctly generated. It cannot recover prover's identity.
   * Only the accountabilty authority can recover prover's identity.
   *
   * @p credential, input, a randomized PS signature
   * @p proof, input, the NIZK proof of the PS signature
   * @p id_recovery_token, input, the identity recovery token that can only be parsed by the accountability authority
   * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority
   * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
   * @return true if verification succeeds; otherwise, return false
   */
  bool
  zk_verify_credential_with_accountability(const PSCredential& credential, const PSCredProof& proof,
                                           const IdRecoveryToken& id_recovery_token,
                                           const G1Point& authority_pk, const std::string& associated_data);

private:
  std::shared_ptr<PSPubKey> m_pk;
  Fr m_t1; // used in commitment attributes
};

#endif // PS_SRC_PS_H_