## Draft ERC - Managing lists for trusted smart contract identifiers  

### Introduction

It is increasing clear that we will need a way to use identifiers in the blockchain space, so much so that there needs to be an easy way for a service to query a contract like this to check if an attestation is valid by an issuers contract.

This ERC proposes a way to manage lists of issuer contracts and their corresponding attestation capacity.

### What's included in this draft

In this draft, we have include a basic implementation and interface as well as examples of using such a list in future.

### The purpose of this ERC

In recent news, the New Zealand government decided to crack down on foreign property owners; to buy property in New Zealand now, you need to be a NZ/AU citizen.

Cases like this are a perfect example of the need for an ERC like this, as they allow you to receive a cryptographic signature from an authority which proves you are a citizen, and maps the attesters key to a smart contract.

When you go to buy the property through a smart contract, the attesters key is checked against a list manager like this, validated against the corresponding contract and checked that it's capacity is high enough to allow purchase of property.

Note: this is one piece of the puzzle, it also requires ERC's like these two: (TODO LINK)

### Draft spec with examples

./ManagedList.sol

### Relevant ERC drafts
