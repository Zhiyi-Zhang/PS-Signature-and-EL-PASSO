# Documentation

Importantly, all the functions require the function call `initPairing()` at the very beginning of the program.
It is recommended to call this function in your main function before calling functions provided by this library.

A complete documentation can be found in the in-line comments of headers files in `src` directory.

## 1. PS Signature and EL PASSO Support

### 1.1 Signer: Key Generation

Use PSSigner to generate the public/private key pair over a known number.
The number indicates how many attributes will be covered by future signatures.
Therefore, here, the PSSigner should take a maximum value of attribute number based on the application scenario.

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
```

### 1.2 Requester: Credential Request Generation

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

### 1.3 Signer: Verify Request and Sign the Credential

Use PSSigner to sign the request.
**Importantly, `el_passo_provide_id` will invoke Non-interactive Zero-knowledge Schnorr Verification Protocol to verify requester's ownership of hidden attributes.**

```C++
PSCredential cred;
bool isValid = signer.el_passo_provide_id(request, "associated-data", cred); // the cred will be generated if the request is valid
```

### 1.4 Requester: Unblind, Verify, and Randomize the Credential

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

### 1.5 Requester: Zero-knowledge proof of the Credential

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

## 2. Encoding/Decoding

We provide `PSBuffer` for encoding and decoding of all PS data structure (i.e., public key, credential, ID proof, ID request).

* Use `PSDataStructure.toBufferString()` to encode the a PS data structure into a `PSBuffer` (which is a byte vector).
* Use `PSBuffer.toBase64()` to encode the buffer into a base64 string.
* Use `PSDataStructure::fromBufferString()` to decode a PS data structure from `PSBuffer`.
* Use `PSBuffer::fromBase64()` to decode `PSBuffer` from a base64 string.

Using PS public key as an example:

```C++
PSSigner signer;
auto pk = signer.key_gen(3); // key pair for 3 attributes at most
auto pkBuffer = pk.toBufferString(); // can be used in network transmission
auto base64Str = pkBuffer.toBase64(); // can be used in JSON
```

```C++
auto pkBuffer = PSBuffer::fromBase64(base64Str); // from base64
auto pk = PSPubKey::fromBufferString(pkBuffer); // from buffer string
```
