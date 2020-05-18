
# Problem

A user, Alice, wishes to send ethers to Bob who doesn't have an Ethereum address. Alice, however, knows an identifier of Bob that can be attested. e.g. Bob's email address or Bob's mobile phone number.

The knowledge to be attested, e.g. email, can't be learned from an observer with access to the Ethereum blockchian.



## Protocol

1. Alice prepare by learning Bob's identifier 𝑥, picking a random salt 𝑠. Calculate ℎ(𝑥, 𝑠) as 𝑦, then ℎ(𝑦) as 𝑧.

2. Alice signs a cheque (a message that depends on an attestation) that asks her smart contract to pay out if someone sends a transaction which contains:

    - a 𝑦 where ℎ(𝑦) = 𝑧.

    - a known attestor's signature that binds 𝑦 to the signer of the transaction

3. Alice pass 𝑠, the cheque together to Bob.

4. Bob gets 𝑦 by calculating ℎ(𝑥, 𝑠) and get an attestor's signature which binds 𝑦 and his public key. To convince the attestor, Bob has to providing 𝑥, 𝑠 and verify to the attestor that he owns 𝑥 identifier.

5. Now Bob has everything to make the smart contract spit out the money. He signs a transaction and get the money.

## Improvement

However this protocol would require Bob to get a new attestation for each transfer to his mail address.

When the protocol finishes, Bob would have obtained an attestation on his email address and Alice's salt (to his newly creted etherem address). Suppose another sender, Carol, asks for a different attestation, Bob could re-use the attestation provide that:

1. Bob stores the salt 𝑠 from the first transfer to his mail.
2. We can perform a group exponentiation over a large group in the smart contract.

Assume Bob holds an assertion to the value 𝑦 such that 𝑦=ℎ(𝑥)ˢ for some 𝑠 over some sufficiently large multiplicative group. The smart contract accepts a transfer request to Bob for any reference value 𝑦′ if he can present an assertion on the value 𝑦 along with a value 𝑎 s.t. 𝑦ᵃ=𝑦′

This means that the first time someone transfers money to Bob he will use 𝑎=1 and the smart contract will simply verify the assertion 𝑦¹=𝑦. However, next time someone transfers money to Bob they will send 𝑦’=ℎ(𝑥)ˢ′.

Bob can compute the value 𝑎=𝑠⁻¹𝑠′, but only because he knows 𝑠 and 𝑠′. Other parties are not able to compute this value unless they can solve the discreet log problem. 

