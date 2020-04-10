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

  // To simplify the implementation, @p attributes_to_commitment concatenated with @p plaintext_attributes
  // must be equal to attributes parameter used in PSRequester::verify (the order of attributes matters).
  // Therefore, a PSRequester should divide all attributes into two sub lists (order won't change), where
  // the first @p attributes_to_commitment.size() attributes will be hidden from the credential verifier.
  std::shared_ptr<PSCredProof>
  prove_credentail(const PSCredential& credential,
                   const std::list<std::string> attributes_to_commitment,
                   const std::list<std::string> plaintext_attributes);

private:
  std::shared_ptr<PSPubKey> m_pk;
  Fr m_t1; // used in commitment attributes
  Fr m_t2; // used in randomize signature
};

#endif // PS_SRC_PS_H_