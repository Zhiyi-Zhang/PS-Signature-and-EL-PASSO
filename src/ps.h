#ifndef PS_SRC_PS_H_
#define PS_SRC_PS_H_

#include <string>
#include <iostream>
#include <mcl/bls12_381.hpp>

using namespace mcl::bls12;

// In this PS implementation, the commitmented attributes goes first and plaintext attribtues goes after
// Prerequisite: initPairing();

class PSSigner
{
public:
  typedef std::unique_ptr<PSSigner> Ptr;

  PSSigner(size_t attribute_num, const G1& g, const G2& gg);

  std::tuple<G1, G2, G2, std::vector<G1>, std::vector<G2>>
  key_gen();

  bool
  sign_cred_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                    const std::vector<std::string>& attributes,
                    const std::string& associated_data, G1& sig1, G1& sig2) const;

  bool
  nizk_verify_request(const G1& A, const Fr& c, const std::vector<Fr>& rs,
                      const std::vector<std::string>& attributes,
                      const std::string& associated_data) const;

  std::tuple<G1, G1>
  sign_hybrid(const G1& A, const std::vector<std::string>& attributes) const;

  std::tuple<G1, G1>
  sign_commitment(const G1& commitment) const;

private:
  size_t m_attribute_num;
  G1 m_g; // G1 generator
	G2 m_gg; // G2 generator
  Fr m_sk_x; // private key, x
  G1 m_sk_X; // private key, X
  G2 m_pk_XX; // public key, XX
  std::vector<G1> m_pk_Yi; // public key, yi
  std::vector<G2> m_pk_YYi; // public key, yyi
};

class PSRequester
{
public:
  typedef std::unique_ptr<PSRequester> Ptr;

  PSRequester();

  void
  init_with_pk(const G1& g, const G2& gg, const G2& XX,
               const std::vector<G1>& Yi, const std::vector<G2>& YYi);

  std::tuple<G1, Fr, std::vector<Fr>, std::vector<std::string>>
  generate_request(const std::vector<std::tuple<std::string, bool>> attributes, // string is the attribute, bool whether to hide
                   const std::string& associated_data);

  std::tuple<G1, G1>
  unblind_credential(const G1& sig1, const G1& sig2) const;

  bool
  verify(const G1& sig1, const G1& sig2, const std::vector<std::string>& all_attributes) const;

  std::tuple<G1, G1>
  randomize_credential(const G1& sig1, const G1& sig2) const;

  // /**
  //  * Generate NIZK proof of the credential.
  //  * To simplify the implementation, @p attributes_to_commitment concatenated with @p plaintext_attributes
  //  * must be equal to attributes parameter used in PSRequester::verify (the order of attributes matters).
  //  * Therefore, a PSRequester should divide all attributes into two sub lists (order won't change), where
  //  * the first @p attributes_to_commitment.size() attributes will be hidden from the credential verifier.
  //  *
  //  * @p credential, input, the PS signature to prove
  //  * @p attributes_to_commitment, input, the attributes to hide from the verifier
  //  * @p plaintext_attributes, input, the attribtues to disclose to the verifier
  //  * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
  //  * @return a tuple of the randomized credential and the proof of the credential
  //  */
  // std::tuple<std::shared_ptr<PSCredential>, std::shared_ptr<PSCredProof>>
  // zk_prove_credentail(const PSCredential& credential,
  //                     const std::list<std::string> attributes_to_commitment,
  //                     const std::list<std::string> plaintext_attributes,
  //                     const std::string& associated_data);

  // /**
  //  * Verify the NIZK proof of the credential.
  //  *
  //  * @p credential, input, a randomized PS signature
  //  * @p proof, input, the NIZK proof of the PS signature
  //  * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
  //  * @return true if verification succeeds; otherwise, return false
  //  */
  // bool
  // zk_verify_credential(const PSCredential& credential, const PSCredProof& proof,
  //                      const std::string& associated_data);

  // /**
  //  * Generate NIZK proof of the credential and a identity recovery token.
  //  * Only the accountabilty authority can recover prover's identity from the identity recovery token.
  //  *
  //  * @p credential, input, the PS signature to prove
  //  * @p attributes_to_commitment, input, the attributes to hide from the verifier
  //  * @p plaintext_attributes, input, the attribtues to disclose to the verifier
  //  * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
  //  * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority
  //  * @p identity_attribute, input, the identity attribute to hide in the identity recovery token, must be a attribute in @p attributes_to_commitment
  //  * @p g, input, a G1 point that both prover and verifier agree on for NIZK of the identity recovery token
  //  * @p h, input, a G1 point that both prover and verifier agree on for NIZK of the identity recovery token
  //  * @return a tuple of the randomized credential, the proof of the credential, and an identity recovery secret with its proof
  //  */
  std::tuple<G1, G1, G2, G1, G1, G1, Fr, std::vector<Fr>, std::vector<std::string>> // sig1, sig2, k, phi, E1, E2, c, rs
  el_passo_prove_id(const G1& sig1, const G1& sig2,
                    const std::vector<std::tuple<std::string, bool>> attributes,
                    const std::string& associated_data,
                    const std::string& service_name,
                    const G1& authority_pk, const G1& g, const G1& h);

  // /**
  //  * Verify the NIZK proof of the credential and the identity recovery token is correctly generated.
  //  * This function only verify the @p id_recovery_token is correctly generated. It cannot recover prover's identity.
  //  * Only the accountabilty authority can recover prover's identity.
  //  *
  //  * @p credential, input, a randomized PS signature
  //  * @p proof, input, the NIZK proof of the PS signature
  //  * @p id_recovery_token, input, the identity recovery token that can only be parsed by the accountability authority
  //  * @p authority_pk, input, the EL Gamal public key (a G1 point) of an accountability authority
  //  * @p associated_data, input, an associated data bound with the NIZK proof used for authentication
  //  * @return true if verification succeeds; otherwise, return false
  //  */
  // bool
  // zk_verify_credential_with_accountability(const PSCredential& credential, const PSCredProof& proof,
  //                                          const IdRecoveryToken& id_recovery_token,
  //                                          const G1Point& authority_pk, const std::string& associated_data);

private:
  G1 m_g; // G1 generator
	G2 m_gg; // G2 generator
  Fr m_sk_x; // private key, x
  G1 m_sk_X; // private key, X
  G2 m_pk_XX; // public key, XX
  std::vector<G1> m_pk_Yi; // public key, yi
  std::vector<G2> m_pk_YYi; // public key, yyi
  Fr m_t1; // used in commitment attributes
};

#endif // PS_SRC_PS_H_