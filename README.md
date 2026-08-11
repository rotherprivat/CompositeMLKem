# CompositeMLKem

This project provides a .NET implementation of the Post Quantum Cryptography (**PQC**) algorithm "CompositeMLKem". 

[API Documentation](https://rotherprivat.github.io/CompositeMLKem/)

## Disclaimer

This library is provided "**as is**", without warranty of any kind, express or implied. The authors 
and contributors make no guarantees regarding the accuracy, reliability, security, or fitness for a 
particular purpose of this software.

This project utilizes the official NuGet package System.Security.Cryptography.Pkcs, which is 
maintained by Microsoft. All cryptographic operations ultimately rely on the underlying 
implementation provided by the .NET platform. Any vulnerabilities, limitations, or changes in 
behavior originating from this dependency are outside the control of this project.

By using this library, you acknowledge and agree that:

- You are responsible for validating its suitability for your use case.
- You assume all risks associated with its use, including but not limited to security, data loss, or system failure.
- The authors shall not be held liable for any damages arising from the use or misuse of this software.

This library is **not intended to replace professional security audits or compliance requirements**. If 
you are working in a regulated or high-security environment, ensure proper review and testing 
before production use.

(**.NET** is a trademark of Microsoft Corporation.)

## CompositeMLKem

The "CompositeMLKem" algorithm is specified by the [IETF draft](https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html) and the implementation and interfaces are aligned to the [.NET ML-KEM implementation "System.Security.Cryptography.MLKem"](https://learn.microsoft.com/de-de/dotnet/api/system.security.cryptography.mlkem).
It implements a composition of the PQC-algorithm "ML-KEM" and a traditional KEM algorithm.

Classes:
- CompositeMLKem
- CompositeMLKemAlgorithm

### Motivation

The .NET version 10.0.2 (SDK 10.0.102) provides implementations of the major PQC-algorithms
 recommended by NIST:

| Purpose | Algorithm |
| --- | --- |
| Key exchange | ["ML-KEM" FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) |
| Digital signature | ["ML-DSA" FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |

As well as the "CompositeMLDsa" algorithm according to the IETF specification, which is a composition of 
the "ML-DSA"- and a traditional digital signing algorithm.

A composite variant of the "ML-KEM" algorithm is not available.

**Why do we need composite algorithms?**

The PQC-algorithms are very young and not totally trusted and not field proven, therefore it 
is considered risky to switch totally to new algorithms. Using a composition of PQC- and 
traditional algorithms in the phase of transition will reduce this risk, an attacker needs to break both 
algorithms, so things won’t get worse.

Some more readings to this on [postquantum.com](https://postquantum.com/post-quantum/hybrid-cryptography-pqc/#why-hybrid-cryptography-ensuring-security-through-transition).

### Restrictions

This version only provides the following algorithm combinations:

| Composite KEM | ML-KEM | Traditional | Combiner |
| --- | --- | --- | --- |
| MLKEM768-RSA2048-SHA3-256 | ML-KEM-768 | RSA, 2048 | SHA3-256 |
| MLKEM768-RSA3072-SHA3-256 | ML-KEM-768 | RSA, 3072 | SHA3-256 |
| MLKEM768-RSA4096-SHA3-256 | ML-KEM-768 | RSA, 4096 | SHA3-256 |
| MLKEM768-ECDH-P256-SHA3-256 | ML-KEM-768 | ECDH, secp256r1 | SHA3-256 |
| MLKEM768-ECDH-P384-SHA3-256 | ML-KEM-768 | ECDH, secp384r1 | SHA3-256 |
| MLKEM768-ECDH-brainpoolP256r1-SHA3-256 | ML-KEM-768 | ECDH, brainpoolP256r1 | SHA3-256 |
| MLKEM1024-RSA3072-SHA3-256 | ML-KEM-1024 | RSA, 3072 | SHA3-256 |
| MLKEM1024-ECDH-P384-SHA3-256 | ML-KEM-1024 | ECDH, secp384r1 | SHA3-256 |
| MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 | ML-KEM-1024 | ECDH, brainpoolP384r1 | SHA3-256 |
| MLKEM1024-ECDH-P521-SHA3-256 | ML-KEM-1024 | ECDH, secp521r1 | SHA3-256 |



### How to use

The "CompositeMLKem" class will be used in the same way as the .NET MLKem ^class^.

Roles:
- Alice: Initiator of communication, owner of private key
- Bob: Communication partner

Workflow:
1. Alice: Generate the key material according to the required combined algorithm (Alice). The private key should be handled confidentially by Alice.
2. Provide Bob, your communication partner, with the encapsulation key (public key)
3. Bob: Generate the local copy of the shared secret and a ciphertext (Encapsulation). The shared key should be handled confidentially by Bob.
4. Forward the ciphertext to Alice.
5. Alice: Generate the local copy of the shared secret by Decapsulating the ciphertext from Bob.
6. Alice and Bob can use the shared secret to encrypt and decrypt exchanged messages.

C# code example:

```C#
// Generate the key material
var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;
using var alice = CompositeMLKem.GenerateKey(algorithm);

var derPublicKey = alice.ExportSubjectPublicKeyInfo();

// Forward derPublicKey to Bob
using var bob = CompositeMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

bob.Encapsulate(out var ciphertext, out var bobsSecret);
// Bob will use bobsSecret

// Forward ciphertext to Alice
var aliceSecret = alice.Decapsulate(ciphertext);
// Alice will use aliceSecret
```
