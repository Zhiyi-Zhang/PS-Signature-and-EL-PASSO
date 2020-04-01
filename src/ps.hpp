#include "ps.pb.h"
#include <string>
#include <iostream>
#include <list>
#include <mcl/bls12_381.hpp>

using namespace mcl::bls12;

class PS
{
public:
  typedef std::unique_ptr<PS> Ptr;

  PS();

  std::shared_ptr<PubKey>
  key_gen(const std::list<std::string>& attributes);

  std::shared_ptr<Credential>
  sign_hybrid(const PubKey& pk, const G1& gt, const std::list<G1>& c_attributes, const std::list<std::string>& attributes);

  std::shared_ptr<Credential>
  sign_commitment(const PubKey& pk, const G1& commitment);

  void
  verify();

private:
  G1 m_g;
	G2 m_gg;
  Fp m_x; // sk1
  G1 m_X; // sk2
};

// class PSClient
// {
// public:
//   typedef std::unique_ptr<PSClient> Ptr;

//   PSClient();

//   static G2
//   commit();

// };