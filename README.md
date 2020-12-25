# TokenScript - Attestation

This repository host the attestation stream of work under TokenScript. Discussion goes to the forum https://community.tokenscript.org/

## What is attestation

In short, an attestation can be likened to a token created off-chain and
usable on-chain. An example of an attestation would be a Devcon ticket.
See document here: http://tokenscript.org/Attestation.html

## In this Repo

This repository has the following content:

paper
: the paper behind the design of this project. The current version there is dated (2018) and doesn't reflect the new work in the last a few years. The current focus is the [cheque/attestation protocol](http://tokenscript.org/Cheque/send_token_by_identifier.html)

src
:the implementation of the attestation and protocols. We use a Java-Solidity model for quick prototyping - testing

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


# ERC publications

ERC's related to this stream of work are:

[ERC1386](https://github.com/ethereum/EIPs/issues/1386), [ERC1387](https://github.com/ethereum/EIPs/issues/1387) & [ERC1388](https://github.com/ethereum/EIPs/issues/1388)

