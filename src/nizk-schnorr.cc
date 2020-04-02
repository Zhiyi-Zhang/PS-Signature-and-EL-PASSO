#include "nizk-schnorr.h"
#include <iostream>

using namespace mcl::bls12;

// Prerequisite: initPairing()

void
nizk_schnorr_prove(const G1& g, const Fp& a,
                   const std::string& associated_data,
                   G1& A, G1& V, Fp& r)
{
  Fp m_v, m_c, m_ac;
  G1::mul(A, g, a);
  // non-interactive schnorr protocol: V
  m_v.setRand();
  G1::mul(V, g, m_v);
  // non-interactive schnorr protocol: r
  cybozu::Sha256 digest_engine;
  digest_engine.update(g.serializeToHexStr());
  digest_engine.update(V.serializeToHexStr());
  digest_engine.update(A.serializeToHexStr());
  auto schnorr_hash_str = digest_engine.digest(associated_data);
  m_c.setHashOf(schnorr_hash_str);
  std::cout << m_c.serializeToHexStr() << std::endl;
  Fp::mul(m_ac, a, m_c);
  Fp::sub(r, m_v, m_ac);
}

bool
nizk_schnorr_verify(const G1& g, const G1& A, const G1& V,
                    const Fp& r, const std::string& associated_data)
{
  G1 m_result, m_gr, m_ac;
  Fp m_c;
  // c
  cybozu::Sha256 digest_engine;
  digest_engine.update(g.serializeToHexStr());
  digest_engine.update(V.serializeToHexStr());
  digest_engine.update(A.serializeToHexStr());
  auto schnorr_hash_str = digest_engine.digest(associated_data);
  m_c.setHashOf(schnorr_hash_str);
  std::cout << m_c.serializeToHexStr() << std::endl;
  // check
  G1::mul(m_gr, g, r);
  G1::mul(m_ac, A, m_c);
  G1::add(m_result, m_gr, m_ac);
  return V == m_result;
}