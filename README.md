# Short Randomizable Signatures (PS Signatures) and EL PASSO Implementation in C++ and WebAssembly

![master-build](https://github.com/Zhiyi-Zhang/PS-Signature-and-EL-PASSO/workflows/master_build/badge.svg) ![docker-build](https://github.com/Zhiyi-Zhang/PS-Signature-and-EL-PASSO/workflows/docker_build/badge.svg)

**Author**: Zhiyi Zhang (zhiyi@cs.ucla.edu)

## 1. Overview

This library implements (i) PS Signature in C++ and WebAssembly and (ii) [EL PASSO](https://arxiv.org/abs/2002.10289).

* PS Signature is a signature scheme that is efficient and randomizable. That is, after generating a PS signature, the signature can be randomized so that it cannot be related to its original presence. This can be widely used for privacy-preserving systems.
* EL PASSO is a privacy-preserving Single Sign-On (SSO) system. It implements anonymous credentials, enables selective attribute disclosure, and allows users to prove properties about their identity without revealing it in the clear.

A certificate based on PS Signature following EL PASSO protocol is privacy-preserving:

* The signer cannot learn the data being signed. The signer can only verify the correctness of the data through zero-knowledge proofs.
* Each certificate can be randomized so as to preserve certificate owner's privacy while a randomized certificate is still valid.

## 1.1 An example application scenario

To illustrate the use of our system, let's assume a user Alice is a legit user of Facebook (an Identity Provider or IdP in short) and she wants to login to a website (a Relying Party or RP in short) with her Facebook account.

First, Alice can get a PS Signature certificate for her attributes `secret-key:123`, `name: alice`, `email: alice@example.com`, and `age: 19`.
When applying the certificate from Facebook, Alice can hide the value of `secret-key:123` and prove the ownership of `secret-key:123` to the Facebook through zero-knowledge proofs.

After Facebook issues Alice the certificate, Alice can further randomize the certificate and use the randomized certificate to prove her identity to the website.
In addition, Alice can select which attributes to share with the website; for example, Alice can select only to share her name `name: alice` and at the same time, without sharing her age, proves her age is larger than 18.
The Website, by verifying the certificate with Facebook's public key, can ensure Alice is a legit user of Facebook and see the revealed attributes.

At the same time, Alice cannot register more than one account (sybil attack) on the website with the same certificate and Facebook cannot link the later certificate with Alice.

Based on the application scenario, EL PASSO can also be built to provide followings desired features with simple updates as stated in our [paper](https://arxiv.org/abs/2002.10289):

* Two factor authentication (2FA).
* Lost recover when Alice lost her certificate.
* Identity information recovery with the help of one or a number of authorities in case a user misbehaves at the RP.

## 1.2 To cite our work

```ascii
@article{zhang2020elpasso,
  title={EL PASSO: Efficient and Lightweight Privacy-preserving Single Sign On},
  author={Zhang, Zhiyi and Król, Michał and Sonnino, Alberto and Zhang, Lixia and Riviere, Etienne},
  journal={Proceedings on Privacy Enhancing Technologies},
  volume={2021},
  number={2},
  publisher={Sciendo}
}
```

## 2. Quick Start

### 2.1 Download

```bash
git clone --recurse-submodules https://github.com/Zhiyi-Zhang/PSSignature.git
```

### 2.2 Compile and Test with Make

The first step is to compile and install MCL library, which is already a submodule of the repo.

```bash
make mcl
```

If the submodule cannot be found, you can update the submodule with the following command.

```bash
git submodule update --init
```

Then, you can simply build and test PSSignature and EL PASSO with `make` and `make check`.

```bash
make
make check
```

### 2.3 Build with WebAssembly

Our library supports the use of Web Assembly (WASM) so that web applications can use the PS Signature and EL PASSO system.

To compile the PS signature test file into a HTML and test it with your browser.

```bash
make el-pass-wasm
```

Then, you should have `wasm-tests.js`, `wasm-tests.wasm`, and `wasm-tests.html` in a new directory called `wasm-build`.
To check the output in the browser, you can serve the html with python.

```bash
cd wasm-build
python3 -m http.server 8080
```

After that, you can open your browser and visit `http://0.0.0.0:8080/ps-tests.html`.
To run the test and see output on your browser, click the button `run-tests` to start.

Note that you can also find each individual module (i.e., IdP, RP, User) in `wasm-build`.
You can develop your own JS code based on these modules for your own application needs.

### 2.4 Build with docker

You can run our codebase in docker as well. This require you must have installed [docker](https://www.docker.com/).

First, create a new image tagged `elpasso` from the `Dockerfile` in the repo directory.

```bash
docker image build -t elpasso .
```

Then, run the tests in a docker container.

```bash
docker run elpasso
```

## 3. Documentation

This library mainly provides following supports.

Importantly, all the functions require the function call `initPairing()` at the very beginning of the program.
It is recommended to call this function in your main function before calling functions provided by this library.

A complete documentation can be found in the in-line comments of headers files in `src` directory.

### 3.1. PS Signature and EL PASSO Support

#### 3.1.1 Signer: Key Generation

Use PSSigner to generate the public/private key pair over a known number.
The number indicates how many attributes will be covered by future signatures.
Therefore, here, the PSSigner should take a maximum value of attribute number based on the application scenario.

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
```

#### 3.1.2 Requester: Credential Request Generation

Use PSRequester to generate a signature request over hidden attributes and plaintext attributes.
Importantly, `el_passo_request_id` will invoke Non-interactive Zero-knowledge Schnorr Prove Protocol to generate proof of ownership of hidden attributes.

```C++
PSRequester user(pk); // pk should be delivered to users through a secure channel, e.g., out-of-band
std::vector<std::tuple<std::string, bool>> attributes; // attributes, the bool indicate whether an attribute should be hidden from the IdP
attributes.push_back(std::make_tuple("secret1", true)); // hidden attribute
attributes.push_back(std::make_tuple("secret2", true)); // hidden attribute
attributes.push_back(std::make_tuple("plain1", false)); // plaintext attribute
auto request = user.el_passo_request_id(attributes, "associated-data"); // a piece of associated data is used with Schnorr Zero Knowledge Proof
```

#### 3.1.3 Signer: Verify Request and Sign the Credential

Use PSSigner to sign the request.
**Importantly, `el_passo_provide_id` will invoke Non-interactive Zero-knowledge Schnorr Verification Protocol to verify requester's ownership of hidden attributes.**

```C++
PSCredential cred;
bool isValid = signer.el_passo_provide_id(request, "associated-data", cred); // the cred will be generated if the request is valid
```

#### 3.1.4 Requester: Unblind, Verify, and Randomize the Credential

Use PSRequester to unblind the credential, verify the credential, and further randomize the credential.

```C++
auto ubld_cred = user.unblind_credential(cred); // unblind signature
std::list<std::string> all_attributes;
all_attributes.push_back("secret1");
all_attributes.push_back("secret2");
all_attributes.push_back("plain1");
if (!user.verify(ubld_cred, all_attributes)) { // verify signature
  // verification of unblinded credential failed
}
auto rnd_cred = user.randomize_credential(ubld_cred); // randomize signature
if (!user.verify(rnd_cred, all_attributes)) { // verify randomized signature
  // verification of randomized credential failed
}
```

#### 3.1.5 Requester: Zero-knowledge proof of the Credential

Use PSRequester to zero-knowledge prove the ownership of the credential to a RP.
In this process, the owner of the credential can decide which attributes to reveal to the verifier.
In addition, when the RP requires identity information recovery in case a user misbehaves, a authorized party's public key can be used to generate a token for identity recovery.

```C++
G1 authority_pk; // authority's pk should be delivered to users and RPs through a secure channel
G1 h; // the G1 generator used by the IdP to generate unique id for the user
G1 g; // a G1 generator used for generating the identity recovery token
...
std::vector<std::tuple<std::string, bool>> attributes;
attributes.push_back(std::make_tuple("secret1", true)); // attribute kept by the user
attributes.push_back(std::make_tuple("secret1", true)); // attribute kept by the user
attributes.push_back(std::make_tuple("plain1", false)); // attribute added by the user
attributes.push_back(std::make_tuple("plain2", false)); // new attribute added by the IdP
attributes.push_back(std::make_tuple("plain3", false)); // new attribute added by the IdP
auto proveID = user.el_passo_prove_id(ubld_sig, attributes, "associated-data", "rp1", authority_pk, g, h)

PSVerifier rp(pk); // pk should be delivered to RPs through a secure channel, e.g., out-of-band
if (!bool result = rp.el_passo_verify_id(proveID, "associated-data", "rp1", authority_pk, g, h);) {
  // verification of user's request failed
}
```

### 3.2 Encoding/Decoding

We provide `PSBuffer` for encoding and decoding of all PS data structure (i.e., public key, credential, ID proof, ID request).

* Use `PSDataStructure.toBufferString()` to encode the a PS data structure into a `PSBuffer` (which is a byte vector).
* Use `PSBuffer.toBase64()` to encode the buffer into a Base 64 string.
* Use `PSDataStructure::fromBufferString()` to decode a PS data structure from `PSBuffer`.
* Use `PSBuffer::fromBase64()` to decode `PSBuffer` from a base 64 string.

Using PS public key as an example:

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
auto pkBuffer = pk.toBufferString(); // can be used in network transmission
auto base64Str = pkBuffer.toBase64(); // can be used in JSON
```

```C++
auto pkBuffer = PSBuffer::fromBase64(base64Str); // from base 64
auto pk = PSPubKey::fromBufferString(pkBuffer); // from buffer string
```
