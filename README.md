# Blockchain Attestations

Attestation is a cryptographically signed proof by an attestor. For example, a marriage document is an attestation signed by a witness.

In many cases, an attestation influences value, for example, the medical certificate signed by a doctor entitles the employee for paid leave; a warranty entitles the free repair service.

In many other cases, an attestation represents value, e.g. a ticket for FIFA Worldcup. In such case, it is like Non-fungible Tokens. The relationship between attestation and non-fungible tokens will be apparent later.

Attestation can be issued off-chain and used on-chain. This is important for two reasons.

First, attestations necessarily carry private information. For example, in the case of identity attestation, the birth date; in the case of mobile phone warranty, the IMEI number of the phone purchased. Such private information, if leaked on the blockchain, will have a financial consequence (e.g. scam).

Second, attestation is often too trivial to justify a paid transaction. For example, an attestation that a video game player has killing 100 enemies with a knife. A real world example would be a voucher that can be redeemed for a coffee. Such attestations exist outside of any blockchain, but may eventually lead to its use on the blockchain for some users. For example, when the previous badge of 100 knife kill entitles the player a discount to buy a pre-sale sequel from a smart-contract.

Attestations are ideal for identifying purposes. An individual's identity can't exist on the blockchain because the word encompasses too much information and obligations, but an aspect of identity can be testified by an attestation. Such attestations are issued on the subject's public keys. Age attestation and driving capacity attestation are two good examples of such identity attestations.

This repository has the following content by folders:

paper
: the paper behind the design of this project. To read, get the PDF from releases tab: https://github.com/alpha-wallet/ethereum-attestation/releases

ethereum/lib
: lib for smart contracts which uses attestations

ethereum/issuers
: example smart contracts used by issuers, for example, revocation list management.

ethereum/trustlist
: members of trustlists to be adopted by smart contracts

ethereum/experiments
: work not in the published specifications

ethereum/example-james-squire
: an example to be used in your projects which requires attestations
