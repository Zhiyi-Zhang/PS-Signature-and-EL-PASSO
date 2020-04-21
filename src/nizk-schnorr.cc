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
  m_v.setByCSPRNG();
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

void
nizk_schnorr_prove_with_two_bases(const G1& g, const G1& h, const Fr& a, const Fr& b, const std::string& associated_data,
                                  G1& A, G1& V, Fr& r1, Fr& r2)
{
  Fr m_v1, m_v2, m_c, m_ac, m_bc;
  G1 A1, A2;
  G1::mul(A1, g, a);
  G1::mul(A2, h, b);
  G1::add(A, A1, A2);
  // non-interactive schnorr protocol: V
  G1 V1, V2;
  m_v1.setByCSPRNG();
  m_v2.setByCSPRNG();
  G1::mul(V1, g, m_v1);
  G1::mul(V2, h, m_v2);
  G1::add(V, V1, V2);
  // non-interactive schnorr protocol: r
  G1 gh;
  G1::add(gh, g, h);
  cybozu::Sha256 digest_engine;
  digest_engine.update(gh.serializeToHexStr());
  digest_engine.update(V.serializeToHexStr());
  digest_engine.update(A.serializeToHexStr());
  auto schnorr_hash_str = digest_engine.digest(associated_data);
  m_c.setHashOf(schnorr_hash_str);
  Fr::mul(m_ac, a, m_c);
  Fr::sub(r1, m_v1, m_ac);
  Fr::mul(m_bc, b, m_c);
  Fr::sub(r2, m_v2, m_bc);
}

bool
nizk_schnorr_verify_with_two_bases(const G1& g, const G1& h, const G1& A, const G1& V, Fr& r1, Fr& r2,
                                   const std::string& associated_data)
{
  G1 m_result, m_gr1, m_hr2, m_ac, m_bc;
  Fr m_c;
  // c
  G1 gh;
  G1::add(gh, g, h);
  cybozu::Sha256 digest_engine;
  digest_engine.update(gh.serializeToHexStr());
  digest_engine.update(V.serializeToHexStr());
  digest_engine.update(A.serializeToHexStr());
  auto schnorr_hash_str = digest_engine.digest(associated_data);
  m_c.setHashOf(schnorr_hash_str);
  // check
  G1::mul(m_gr1, g, r1);
  G1::mul(m_hr2, h, r2);
  G1::mul(m_ac, A, m_c);
  G1::add(m_result, m_gr1, m_hr2);
  G1::add(m_result, m_result, m_ac);
  return V.serializeToHexStr() == m_result.serializeToHexStr();
}