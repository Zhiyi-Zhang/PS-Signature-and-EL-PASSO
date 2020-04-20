# Short Randomizable Signatures (PS Signatures) Implementation in C++

Author: Zhiyi Zhang (zhiyi@cs.ucla.edu)

This library supports the use of certificates based on PS Signature.
The certificate is privacy-preserving:

* The signer cannot learn the data being signed. The signer can only verify the correctness of the data through zero-knowledge proofs.
* Each certificate can be randomized so as to preserve certificate owner's privacy while a randomized certificate is still valid.

For example, Alice wants to get a certificate for attribute `secret1`, `secret2`, and `plaintext1`.
When applying the certificate from a CA, Alice can hide the value of hidden attributes and prove the ownership of `secret1`, `secret2` to the CA through zero-knowledge proofs.
After CA issues Alice the certificate.
Alice can further randomize the certificate.
When Alice use a randomized certificate to prove her identity, even the CA cannot link this certificate with Alice.

## Quick Compile and Test

### Prerequisites

#### 1. [Google Protocol Buffer](https://developers.google.com/protocol-buffers)

The network part relies on Google's protocol buffer.
You should install it for C++.
Check the instructions [here](https://github.com/protocolbuffers/protobuf/tree/master/src#c-installation---unix).

#### 2. [MCL library](https://github.com/herumi/mcl).

First you need to install all the prerequisites of MCL library.
Check it [here](https://github.com/herumi/mcl#installation-requirements).

After that, create a new directory, download MCL library, and install MCL library

```bash
mkdir ps-sig
cd ps-sig
git clone git://github.com/herumi/mcl
cd mcl
make -j4
make install
```

Then, go back to the `ps-sig` directory and download this repository.

```bash
cd ..
git clone https://github.com/Zhiyi-Zhang/PSSignature.git
```

### Compile and Test

Compile it.
```bash
cd PSSignature
make
```

If you encountered any issues with Protocol Buffers used in `ps.pb.cc` and `ps.pb.h`.
You can re-generate them.
```
make protobuf
```

Test it.
```bash
./test-ps
```

## Documentation

This library mainly provides following supports.

Importantly, all the functions require the function call `initPairing()` at the very beginning of the program.
It is recommended to call this function in your main function before calling functions provided by this library.

### 1. PS Signature Support

#### 1.1 Signer: Key Generation

Use PSSigner to generate the public/private key pair over a known number.
The number indicates how many attributes will be covered by future signatures.
Therefore, here, the PSSigner should take a maximum value of attribute number.

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
```

#### 1.2 Requester: Credential Request Generation

Use PSRequester to generate a signature request over hidden attributes and plaintext attributes.
**Importantly, `generate_request` will invoke Non-interactive Zero-knowledge Schnorr Prove Protocol to generate proof of ownership of hidden attributes.**

```C++
PSRequester user(pk); // pk should be delivered to users through a secure channel, e.g., out-of-band
std::list<std::string> c_attributes; // attributes to be hidden from the signer
c_attributes.push_back("secret1");
c_attributes.push_back("secret2");
std::list<std::string> attributes; // attributes that can be kept as plaintext
attributes.push_back("plain1");
auto request = user.generate_request(c_attributes, attributes);
```

#### 1.3 Signer: Verify Request and Sign the Credential

Use PSSigner to sign the request.
**Importantly, `sign_cred_request` will invoke Non-interactive Zero-knowledge Schnorr Verification Protocol to verify requester's ownership of hidden attributes.**

```C++
auto cred1 = signer.sign_cred_request(*request);
```

#### 1.4 Requester: Unblind, Verify, and Random the Credential

Use PSRequester to unblind the credential, verify the credential, and further randomized the credential.

```C++
auto cred2 = user.unblind_credential(*cred1); // unblind signature
std::list<std::string> all_attributes;
all_attributes.push_back("secret1");
all_attributes.push_back("secret2");
all_attributes.push_back("plain1");
if (!user.verify(*cred2, all_attributes)) { // verify signature
  std::cout << "Verification Failure" << std::endl;
  return;
}
auto cred3 = user.randomize_credential(*cred2); // randomize signature
if (!user.verify(*cred3, all_attributes)) { // verify randomized signature
  std::cout << "verification randomized credential failure" << std::endl;
  return;
}
```

#### 1.5 Requester: Zero-knowledge proof of the Credential

Use PSRequester to zero-knowledge prove the ownership of the credential.
In this process, the owner of the credential can decide which attributes to reveal to the verifier.
In our current implementation, we require c_attributes + attributes must equal to all attributes and the order matters.

```C++
auto [cred3, proof] = user.zk_prove_credentail(*cred2, c_attributes, attributes, "abc");

PSRequester user2(pk);
if (!user2.zk_verify_credential(*cred3, *proof, "abc")) {
  std::cout << "zk proof failure" << std::endl;
  return;
}
```

### 2. Encoding/Decoding of Public Key, Credential Request, and Credential

We use Google Protocol Buffer for encoding and decoding.

Use public key delivery as an example.
Use `SerializeAsString` to encode:

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
std::string encoded_pk = pk.SerializeAsString();
```

Use `ParseFromString` to decode:

```C++
PSPubKey pk;
std::string encoded_pk;
// get pk from the network
if (!pk.ParseFromString(encoded_pk)) {
  std::cout << "Decoding failure" << std::endl;
  return;
}
PSRequester user(pk);
```

### 3. Non-interactive Zero-knowledge Schnorr Protocol

This library implements NIZK schnorr protocol as specified in [RFC 8235](https://tools.ietf.org/html/rfc8235).

For example, you want to prove your ownership of a secret.

```C++
initPairing();
G1 g; // used as the Group generator
hashAndMapToG1(g, "abc", 3); // Select a base point as the generator
Fr secret; // this is your secret
secret.setByCSPRNG();

G1 A, V;
Fr r;
std::string associated_data = "user-id";
nizk_schnorr_prove(g, secret, associated_data, A, V, r); // initialize A, V, and r
bool result = nizk_schnorr_verify(g, A, V, r, associated_data); // verify the proof (A, V, r, associated_data)
if (!result) {
  std::cout << "NIZK schnorr failure" << std::endl;
  return;
}
```
