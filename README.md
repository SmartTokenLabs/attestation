# TokenScript - Attestation

This repository host the attestation libraries TokenScript. Discussion goes to the forum https://community.tokenscript.org/

## What is attestation

In short, an attestation can be likened to a token created off-chain and
usable on-chain. An example of an attestation would be a Devcon ticket.
See document here: http://tokenscript.org/Attestation.html

## Build

You need the following installed:

- JDK (version 11 or higher)
- Gradle (version 7.1.1 is used by our devs)
- node.js (version 15 is used by our devs)

Once you have them installed, run:

    $ gradle build

The build script will run a few tests, resulting a few pem files created in `build/test-results/` directory.

## Try it yourself

To create a jar file for running the demo, run:

    $ gradle shadowJar

Which will create a jar file that you can run in the commandline

    build/libs/attestation-all.jar

There is a walk-through to use the functionalities provided by this library through commandline: [commandline cheque demonstration](cli-cheque-demo.md) and the  [commandline EIP712 attestation demonstration](cli-attestation-demo.md)

## Organisation of this repo

This repository has the following content:

data-modules
:the data modules definitions used in this project

src
:the implementation of the attestation and protocols. We use a Java-Solidity model for quick prototyping - testing.

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

paper
: the paper behind the design of this project. The current version there is dated (2018) and doesn't reflect the new work in the last a few years. The current focus is the [cheque/attestation protocol](http://tokenscript.org/Cheque/send_token_by_identifier.html)


# ERC publications

ERC's related to this stream of work are:

[ERC1386](https://github.com/ethereum/EIPs/issues/1386), [ERC1387](https://github.com/ethereum/EIPs/issues/1387) & [ERC1388](https://github.com/ethereum/EIPs/issues/1388)

