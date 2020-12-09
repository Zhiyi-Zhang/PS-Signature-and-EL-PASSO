#include "ps-encoding.h"

char buf[1024];

static size_t
probeVarSize(size_t var)
{
  if (var < 253) {
    return 1;
  }
  else if (var <= 0xFFFF) {
    return 3;
  }
  return 0;
}

void
PSBuffer::appendType(PSEncodingType type)
{
  this->push_back(static_cast<uint8_t>(type));
}

size_t
PSBuffer::parseType(size_t offset, PSEncodingType& type) const
{
  type = static_cast<PSEncodingType>(this->at(offset));
  return 1;
}

void
PSBuffer::appendVar(size_t var)
{
  if (var < 253) {
    this->push_back(var & 0xFF);
  }
  else if (var <= 0xFFFF) {
    this->push_back(253);
    this->push_back((var >> 8) & 0xFF);
    this->push_back(var & 0xFF);
  }
}

size_t
PSBuffer::parseVar(size_t offset, size_t& var) const
{
  auto firstDigit = this->at(offset);
  if (firstDigit < 253) {
    var = firstDigit;
    return 1;
  }
  else if (firstDigit == 253) {
    var = (this->at(offset + 1) << 8) | this->at(offset + 2);
    return 3;
  }
  return 0;
}

void
PSBuffer::appendG1Element(const G1& g, bool withType)
{
  size_t size = g.serialize(buf, sizeof(buf));
  if (withType) {
    this->reserve(this->size() + probeVarSize(size) + size + 1);
    this->appendType(PSEncodingType::G1);
  }
  else {
    this->reserve(this->size() + probeVarSize(size) + size);
  }
  this->appendVar(size);
  this->insert(this->end(), buf, buf + size);
}

size_t
PSBuffer::parseG1Element(size_t offset, G1& g, bool withType) const
{
  size_t step = 0;
  if (withType) {
    PSEncodingType type;
    step += this->parseType(offset, type);
    if (type != PSEncodingType::G1) {
      return 0;
    }
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  g.deserialize(this->data() + offset + step, size);
  return step + size;
}

void
PSBuffer::appendG2Element(const G2& g, bool withType)
{
  size_t size = g.serialize(buf, sizeof(buf));
  if (withType) {
    this->reserve(this->size() + probeVarSize(size) + size + 1);
    this->appendType(PSEncodingType::G2);
  }
  else {
    this->reserve(this->size() + probeVarSize(size) + size);
  }
  this->appendVar(size);
  this->insert(this->end(), buf, buf + size);
}

size_t
PSBuffer::parseG2Element(size_t offset, G2& g, bool withType) const
{
  size_t step = 0;
  if (withType) {
    PSEncodingType type;
    step += this->parseType(offset, type);
    if (type != PSEncodingType::G2) {
      return 0;
    }
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  g.deserialize(this->data() + offset + step, size);
  return step + size;
}

void
PSBuffer::appendFrElement(const Fr& f, bool withType)
{
  size_t size = f.serialize(buf, sizeof(buf));
  if (withType) {
    this->reserve(this->size() + probeVarSize(size) + size + 1);
    this->appendType(PSEncodingType::Fr);
  }
  else {
    this->reserve(this->size() + probeVarSize(size) + size);
  }
  this->appendVar(size);
  this->insert(this->end(), buf, buf + size);
}

size_t
PSBuffer::parseFrElement(size_t offset, Fr& f, bool withType) const
{
  size_t step = 0;
  if (withType) {
    PSEncodingType type;
    step += this->parseType(offset, type);
    if (type != PSEncodingType::Fr) {
      return 0;
    }
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  f.deserialize(this->data() + offset + step, size);
  return step + size;
}

void
PSBuffer::appendG1List(const std::vector<G1>& gs)
{
  this->reserve(this->size() + 1 + probeVarSize(gs.size()));
  this->appendType(PSEncodingType::G1List);
  this->appendVar(gs.size());
  for (const auto& item : gs) {
    this->appendG1Element(item, false);
  }
}

size_t
PSBuffer::parseG1List(size_t offset, std::vector<G1>& gs) const
{
  size_t step = 0;
  PSEncodingType type;
  step += this->parseType(offset, type);
  if (type != PSEncodingType::G1List) {
    return 0;
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  G1 temp;
  for (size_t i = 0; i < size; i++) {
    step += this->parseG1Element(offset + step, temp, false);
    gs.push_back(temp);
  }
  return step;
}

void
PSBuffer::appendG2List(const std::vector<G2>& gs)
{
  this->reserve(this->size() + 1 + probeVarSize(gs.size()));
  this->appendType(PSEncodingType::G2List);
  this->appendVar(gs.size());
  for (const auto& item : gs) {
    this->appendG2Element(item, false);
  }
}

size_t
PSBuffer::parseG2List(size_t offset, std::vector<G2>& gs) const
{
  size_t step = 0;
  PSEncodingType type;
  step += this->parseType(offset, type);
  if (type != PSEncodingType::G2List) {
    return 0;
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  G2 temp;
  for (size_t i = 0; i < size; i++) {
    step += this->parseG2Element(offset + step, temp, false);
    gs.push_back(temp);
  }
  return step;
}

void
PSBuffer::appendFrList(const std::vector<Fr>& fs)
{
  this->reserve(this->size() + 1 + probeVarSize(fs.size()));
  this->appendType(PSEncodingType::FrList);
  this->appendVar(fs.size());
  for (const auto& item : fs) {
    this->appendFrElement(item, false);
  }
}

size_t
PSBuffer::parseFrList(size_t offset, std::vector<Fr>& fs) const
{
  size_t step = 0;
  PSEncodingType type;
  step += this->parseType(offset, type);
  if (type != PSEncodingType::FrList) {
    return 0;
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  Fr temp;
  for (size_t i = 0; i < size; i++) {
    step += this->parseFrElement(offset + step, temp, false);
    fs.push_back(temp);
  }
  return step;
}

void
PSBuffer::appendStrList(const std::vector<std::string>& strs)
{
  this->reserve(this->size() + 1 + probeVarSize(strs.size()));
  this->appendType(PSEncodingType::StrList);
  this->appendVar(strs.size());
  for (const auto& item : strs) {
    this->reserve(this->size() + probeVarSize(item.size()) + item.size());
    this->appendVar(item.size());
    this->insert(this->end(), item.c_str(), item.c_str() + item.size());
  }
}

size_t
PSBuffer::parseStrList(size_t offset, std::vector<std::string>& strs) const
{
  size_t step = 0;
  PSEncodingType type;
  step += this->parseType(offset, type);
  if (type != PSEncodingType::StrList) {
    return 0;
  }
  size_t size = 0;
  step += this->parseVar(offset + step, size);
  size_t strLen = 0;
  for (size_t i = 0; i < size; i++) {
    step += this->parseVar(offset + step, strLen);
    std::string temp(reinterpret_cast<char const*>(this->data() + offset + step), strLen);
    strs.push_back(temp);
    step += strLen;
  }
  return step;
}

PSBuffer
PSCredential::toBufferString()
{
  PSBuffer buffer;
  buffer.appendG1Element(sig1);
  buffer.appendG1Element(sig2);
  return buffer;
}

PSCredential
PSCredential::fromBufferString(const PSBuffer& buf)
{
  PSCredential credential;
  size_t step = 0;
  step += buf.parseG1Element(step, credential.sig1);
  step += buf.parseG1Element(step, credential.sig2);
  return credential;
}

PSBuffer
PSPubKey::toBufferString()
{
  PSBuffer buffer;
  buffer.appendG1Element(g);
  buffer.appendG2Element(gg);
  buffer.appendG2Element(XX);
  buffer.appendG1List(Yi);
  buffer.appendG2List(YYi);
  return buffer;
}

PSPubKey
PSPubKey::fromBufferString(const PSBuffer& buf)
{
  PSPubKey pubKey;
  size_t step = 0;
  step += buf.parseG1Element(step, pubKey.g);
  step += buf.parseG2Element(step, pubKey.gg);
  step += buf.parseG2Element(step, pubKey.XX);
  step += buf.parseG1List(step, pubKey.Yi);
  step += buf.parseG2List(step, pubKey.YYi);
  return pubKey;
}

PSBuffer
PSCredRequest::toBufferString()
{
  PSBuffer buffer;
  buffer.appendG1Element(A);
  buffer.appendFrElement(c);
  buffer.appendFrList(rs);
  buffer.appendStrList(attributes);
  return buffer;
}

PSCredRequest
PSCredRequest::fromBufferString(const PSBuffer& buf)
{
  PSCredRequest request;
  size_t step = 0;
  step += buf.parseG1Element(step, request.A);
  step += buf.parseFrElement(step, request.c);
  step += buf.parseFrList(step, request.rs);
  step += buf.parseStrList(step, request.attributes);
  return request;
}

PSBuffer
IdProof::toBufferString()
{
  PSBuffer buffer;
  buffer.appendG1Element(sig1);
  buffer.appendG1Element(sig2);
  buffer.appendG2Element(k);
  buffer.appendG1Element(phi);
  buffer.appendFrElement(c);
  buffer.appendFrList(rs);
  buffer.appendStrList(attributes);
  if (E1.has_value() && E2.has_value()) {
    buffer.appendG1Element(E1.value());
    buffer.appendG1Element(E2.value());
  }
  return buffer;
}

IdProof
IdProof::fromBufferString(const PSBuffer& buf)
{
  IdProof proof;
  size_t step = 0;
  step += buf.parseG1Element(step, proof.sig1);
  step += buf.parseG1Element(step, proof.sig2);
  step += buf.parseG2Element(step, proof.k);
  step += buf.parseG1Element(step, proof.phi);
  step += buf.parseFrElement(step, proof.c);
  step += buf.parseFrList(step, proof.rs);
  step += buf.parseStrList(step, proof.attributes);
  if (step < buf.size()) {
    G1 e1, e2;
    step += buf.parseG1Element(step, e1);
    step += buf.parseG1Element(step, e2);
    proof.E1 = e1;
    proof.E2 = e2;
  }
  return proof;
}