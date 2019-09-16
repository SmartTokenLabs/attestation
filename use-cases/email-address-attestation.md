
# Problem

A user, Alice, wishes to send ethers to Bob who doesn't have an Ethereum address. Alice, however, knows something of Bob that can be attested. e.g. Bob's email address.

The knowledge to be attested, e.g. email, can't be learned from an observer with access to the Ethereum blockchian.

# Protocol

1. Alice prepare by learning Bob's email address 𝑥, picking a 𝑠,
calculating ℎ(ℎ(𝑥, 𝑠)) as 𝑧.

2. Alice signs a message that asks her smart contract to pay out if
    someone sends a transaction which contains:

    - a 𝑦 where ℎ(𝑦) = 𝑧, and

    - a known authority's signature that binds 𝑦 to the signer of the
      transaction

3. Alice pass that signed message together with 𝑠 to Bob.

4. Bob gets 𝑦 by calculating ℎ(𝑥, 𝑠) and get an authority's signature
    which binds 𝑦 and his public key. To convince the authority, Bob
    has to providing 𝑥, 𝑠 and verify to the authority that he owns 𝑥
    email address.

5. Now Bob has everything to make the smart contract spit out the
    money. He signs a transaction and get the money.

## Improvement

However this protocol would require Bob to get a new attestation for each
transfer to his mail address.

When the protocol finishes, Bob would have obtained an attestation on
his email address and Alice's salt (to his newly creted etherem
address). Suppose another sender, Carol, asks for a different
attestation, Bob could re-use the attestation provide that:

1. Bob stores the salt 𝑠 from the first transfer to his mail.
2. We can perform a group exponentiation over a large group in the smart contract.

Assume Bob holds an assertion to the value y such that y=H(x)^s for some s over some sufficiently large multiplicative group. The smart contract accepts a transfer request to Bob for any reference value y' if he can present an assertion on the value y along with a value a s.t. y^a=y’

This means that the first time someone transfers money to Bob he will use a=1 and the smart contract will simply verify the assertion y^1=y. However, next time someone transfers money to Bob they will send y’=H(x)^s’. 
Bob can compute the value a=s^{-1}s’, but only because he knows s and s’. Other parties are not able to compute this value unless they can solve the discreet log problem. 