#include "nizk-schnorr.h"
#include <iostream>

using namespace mcl::bls12;

// Prerequisite: initPairing()

void
nizk_schnorr_prove(const G1& g, const Fr& a,
                   const std::string& associated_data,
                   G1& A, G1& V, Fr& r)
{
  Fr m_v, m_c, m_ac;
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
  Fr::mul(m_ac, a, m_c);
  Fr::sub(r, m_v, m_ac);
}

bool
nizk_schnorr_verify(const G1& g, const G1& A, const G1& V,
                    const Fr& r, const std::string& associated_data)
{
  G1 m_result, m_gr, m_ac;
  Fr m_c;
  // c
  cybozu::Sha256 digest_engine;
  digest_engine.update(g.serializeToHexStr());
  digest_engine.update(V.serializeToHexStr());
  digest_engine.update(A.serializeToHexStr());
  auto schnorr_hash_str = digest_engine.digest(associated_data);
  m_c.setHashOf(schnorr_hash_str);
  // check
  G1::mul(m_gr, g, r);
  G1::mul(m_ac, A, m_c);
  G1::add(m_result, m_gr, m_ac);
  return V.serializeToHexStr() == m_result.serializeToHexStr();
}