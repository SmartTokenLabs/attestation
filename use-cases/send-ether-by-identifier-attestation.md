
# Problem

A user, Alice, wishes to send ether to Bob who doesn’t have an Ethereum address. Alice, however, knows an identifier of Bob that can be attested. e.g. Bob’s email address or Bob’s mobile phone number.

The knowledge to be attested, e.g. email, can’t be learned from an observer with access to the Ethereum blockchain.

# Protocol

## Attestation

1. Bob generates an Ethereum key (if he hasn't already) and an attestation key 𝑠.

2. Bob creates the corresponding subject of attestation 𝑦 = 𝑥ˢ.

3. Bob signs a CSR with his identifier (mobile number / email-address) 𝑥 two times, one with his Etheruem key and one with 𝑠.

4. An attestor verifies that Bob owns the identifier 𝑥, both signatures are valid, then issue an attestation that binds his Ethereum address with the subject 𝑦.

### Cheque

1. Alice wishes to send Bob some ether and knows Bob’s identifier. She creates a one-time-key 𝑠’, computes 𝑦’ = 𝑥ˢ’.

2. Alice writes a cheque for anyone to redeem a certain amount of Ether from her smart contract. The cheque requires an 𝑎 such that 𝑦’ = 𝑦ᵃ for a valid attestation on 𝑦.

3. Alice sends 𝑠’ and the cheque to Bob.

### Redeem the Cheque with the Attestation

Bob compute a value 𝑎=𝑠⁻¹𝑠’ and provide

1. 𝑎
2. the attestation (𝑦 is its subject)

The smart contract computes:

1. The attestation is a valid attestation that binds 𝑦 to Bob (transaction sender)’s Ethereum address.
2. That 𝑦ᵃ = 𝑦’
3. That the amount in the attestation is less than Alice’s balance.

If all predicates are satisfied, emits the pay to Bob.
