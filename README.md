
ZK13: A Zero-Knowledge Proof Protocol for Set Membership
=======================================================

ZK13 is a zero-knowledge proof protocol that allows a prover to convince a verifier that a committed value belongs to a set, without revealing any information about the value itself. The protocol is based on the [Pedersen commitment scheme](https://en.wikipedia.org/wiki/Pedersen_commitment) and the [Schwartz-Zippel lemma](https://en.wikipedia.org/wiki/Schwartz%E2%80%93Zippel_lemma).

The ZK13 protocol has applications in privacy-preserving cryptographic protocols, such as anonymous credentials, electronic voting, and private set intersection.

Go-libzk13 is an implementation of the ZK13 protocol in Go. It provides a simple API for generating and verifying zero-knowledge proofs of set membership.

Algorithm Description
---------------------

The ZK13 protocol consists of three main phases:

1. **Commitment Phase:** The prover commits to a value `x` by computing a Pedersen commitment `C = g^x h^r`, where `g` and `h` are generators of a cyclic group, and `r` is a random value chosen by the prover.
2. **Challenge Phase:** The verifier sends a challenge `c` to the prover. The challenge is a random value chosen from a finite field.
3. **Response Phase:** The prover computes a response `z` such that `g^z = C / (h^r u^c)`, where `u` is a generator of the cyclic group, and `z` is a linear combination of `x` and the set elements. The prover sends the response `z` to the verifier.

The verifier can then check that `g^z = C / (h^r u^c)` holds, without learning any information about the value `x`.

Implementation Details
----------------------

Go-libzk13 provides an implementation of the ZK13 protocol in Go. The implementation uses the [bn256](https://godoc.org/github.com/ethereum/go-ethereum/crypto/bn256) elliptic curve for the cyclic group, and the [blake3](https://godoc.org/github.com/zeebo/blake3) hash function for hashing.

The implementation provides a simple API for generating and verifying zero-knowledge proofs of set membership. The API consists of the following functions:

* `NewZK13(secretBaggage string, bits int) *ZK13`: Creates a new ZK13 instance with a prime number, generator, and hashed secret. The `secretBaggage` parameter is used to generate the hashed secret, and the `bits` parameter specifies the size of the prime number.
* `Prover(nonce *big.Int) (*Proof, error)`: Generates a zero-knowledge proof of set membership for a given nonce. The nonce is used to protect against replay attacks.
* `Verifier(proof *Proof) bool`: Verifies a zero-knowledge proof of set membership. Returns `true` if the proof is valid, and `false` otherwise.

Usage
-----

Here's an example of how to use go-libzk13 to generate and verify a zero-knowledge proof of set membership:
```go
package main

import (
    "fmt"
    "github.com/genovatix/go-libzk13/zkp"
    "math/big"
)

func main() {
    // Create a new ZK13 instance with a 2048-bit prime
    zk13 := zkp.NewZK13("shared secret", 2048)

    // Generate a nonce for replay attack protection
    nonce, err := zkp.GenerateNonce(zk13.P())
    if err != nil {
        panic(err)
    }

    // Generate a zero-knowledge proof of set membership
    proof, err := zk13.Prover(nonce)
    if err != nil {
        panic(err)
    }

    // Verify the zero-knowledge proof of set membership
    isValid := zk13.Verifier(proof)
    fmt.Printf("Proof is valid: %v\n", isValid)
}
```
Performance
-----------

Go-libzk13 is designed to be fast and efficient. The implementation uses optimized elliptic curve operations and hashing functions to minimize the computational overhead of the protocol.

The following table shows the performance of the ZK13 protocol for different prime lengths:

| Prime Length | Prover Time (ms) | Verifier Time (ms) |
| ------------ | --------------- | ------------------ |
| 512 | 0.4 | 0.1 |
| 1024 | 1.5 | 0.3 |
| 2048 | 6.1 | 1.2 |
| 2048 + 32 | 6.5 | 1.3 |

The performance measurements were taken on an Intel Core i7-9750H CPU @ 2.60GHz.

Contributing
------------

Go-libzk13 is an open-source project, and contributions are welcome. If you would like to contribute to the project, please open a pull request with your proposed changes.

License
-------

Go-libzk13 is licensed under the [MIT License](https://opensource.org/licenses/MIT).

Contact
-------

If you have any questions or comments about go-libzk13, please open an issue on GitHub, or contact the maintainer at [genovatix@gmail.com](mailto:genovatix@gmail.com).
