
# Attestation data model

## A minimalist attestation

Let's say, Alice wishes to send Bob 1Ξ. However, Alice isn't sure of Bob's Ethereum address. Bob can provide Alice with an attestation, signed by an attestor that both Alice and Bob trust. The attestation serves to bind Bob's email address to his Ethereum Address. It looks like this in an ANS.1-like syntax:

    EmailAttestation  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        email                IA5String,
        beneficiaryAddress   EthereumAddress }

Where `EthereumAddress` is a subtype of `OCTET STRING` with a length limit of 20 bytes. (The `PublicKeyInfo` is left out per blockchain custom started by Vitalik.)

Its signed form might look like this:

    signedEmailAttestation  ::=  SEQUENCE  {
        emailAttestation     EmailAttestation,
        signature            Signature }
        
Assuming:

- A communication channel between Alice and Bob exists, e.g. email.
- Alice knows Bob's email address.

A minimalist protocol would look like this:

1. Alice requests an attestation from Bob.
2. Bob provides an attestation.
3. Alice verifies the attestation and extracts Bob's Ethereum address.
4. Alice sends 1Ξ to Bob's Ethereum address.

## Attestation on the blockchain

In reality, Alice and Bob are likely mobile users who are not always online. With the said protocol, Alice would be online two times to finalise the protocol. First, to ask Bob for the Ethereum address attestation; second time, to send the Ethereum transaction. Ideally, Alice should be able to "send" the money by just knowing Bob's email address, akin to how Paypal works.

Suppose Alice's money is held in a smart contract called `Wallet`, Alice can simplify the protocol by issuing an attestation for her Wallet:

    Cheque ::= SEQUENCE {
        predicate   UTF8String,      # example: "(email=bob@gmail.com)"
        attestor    EthereumAddress, # smart contract which maintains a list
        redeemer    EthereumAddress, # Alice's Wallet
        amount      INTEGER,         # example: 1
        validity    Validity }


This check effectively allows Bob to redeem `amount` amount of money from Alice's `Wallet`. We will redefine `Cheque` later for more generalised uses.

The new protocol would look like this:

1. Alice sends an AttestedCheque to Bob.
2. Bob assembles a transaction to `Wallet` and gets the 1Ξ as a result.

Unlike the previous protocol, in this protocol, the attestations are sent to the Ethereum blockchain, and therefore itself must be in transaction payload.

At this point, attestation meets blockchain, and we are at a crossroad. We have a few possible designs. First, the most V-like (Vitalik style), which you can observe in today's blockchain:

### 1. The most V-like style

`Wallet` has a function like this:

    function redeem(bytes Cheque,           uint256 r, uint256 s, int v,
                    bytes EmailAttestation, uint256 r, uint256 s, int v)

Bob would send a transaction to the `Wallet` calling this function with an instance of `Cheque`, the signature on the cheque, an attestation, the signature on the attestation. The smart contract doles out money according to the amount specified in the cheque, predicated by the cheque. The money is doled out to the `beneficiaryAddress` disregarding the transaction's sender (which could be Alice herself or any 3rd party).

### 2. The middle ground.

`Wallet` has a function like this:

    function redeem(bytes signedCheque, bytes signedEmailAttestation)

Whose ABI is like this:

    {"type": "function",
     "name": "redeem",
     "inputs": [
         {"name": "Cheque", "type": "bytes"},
         {"name": "Attestation", "type": "bytes"}
     ],
     "payable": "false"
    }

Now we need to define some objects. You have seen `signedEmailAttestation` earlier in this chapter. `signedCheque` is defined alike:

    signedCheque  ::=  SEQUENCE  {
        cheque               Cheque,  # To-be-signed Cheque
        signature            Signature }

### 3. The least V-like style.

`Wallet` has a function like this:

    function redeem(bytes redeemable)

Now we need to define redeemable. For this example, it might look like this:

    redeemable ::= SEQUENECE {
        cheque               Cheque,  # To-be-signed Cheque
        chequeSignature      Signature,
        EmailAttestation          EmailAttestation,
        EmailAttestationSignature Signature }

Now I'm going to make the argument that the 3rd method is the best.
