# Problem

A user, Alice, wishes to send ether to Bob who doesn’t have an Ethereum address. Alice, however, knows an identifier of Bob that can be attested. e.g. Bob’s email address or Bob’s mobile phone number.

The identifier to be attested, denoted as 𝑖 (email address or mobile number), can’t be learned from an observer with access to the Ethereum blockchain.

# Protocol

## Attestation

1. Bob generates an Ethereum key (if he hasn't already) and a privacy key 𝑝.

2. Bob creates the corresponding subject of attestation 𝑠 = 𝑖ᵖ.

3. Bob signs a CSR (signing request) with his identifier 𝑖 two times, one with his Etheruem key and one with 𝑝.

4. An attestor verifies that Bob owns the identifier, both signatures are valid, then issue an attestation that binds his Ethereum address with the subject 𝑠.

### Cheque

1. Alice wishes to send Bob some Ether and knows Bob’s identifier 𝑖. She creates a one-time-key 𝑝’, computes 𝑠’ = 𝑖ᵖ’.

2. Alice writes a cheque for anyone to redeem a certain amount of Ether from her smart contract. The cheque requires an 𝑥 such that 𝑠’ = 𝑠ˣ for a valid attestation on subject 𝑠.

3. Alice sends 𝑝’ and the cheque to Bob.

### Redeem the Cheque with the Attestation

Bob computes a value 𝑥=𝑝⁻¹𝑝’ and, in a redeeming transaction, provides

1. 𝑥
2. the attestation (whose subject is 𝑠)

The smart contract computes:

1. The attestation is a valid attestation that binds 𝑠 to Bob (transaction sender)’s Ethereum address.
2. That 𝑠ˣ = 𝑠’
3. That the amount in the attestation is less than Alice’s balance.

If all predicates are satisfied, emits the pay to Bob.
