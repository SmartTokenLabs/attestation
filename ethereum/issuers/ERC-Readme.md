## ERC draft - Issuer framework for identifiers

### Introduction

With the Ethereum world progressing at a rapid pace, we need to take this opportunity to bring about a framework to allow for valid authorities to be issuers of identifiers on the network.

### Purpose

We hope to provide an easy to use framework for managing issuers via a smart contract so that we can all start seamlessly using blockchain and other off chain services which require a valid identifier.

### Example use cases

Let's say that our friend, Alice, wants to buy a bottle of wine to consume with her friends. She wants to do the order online and have it delivered to her home address whilst paying for it using Ether.

Alice has a cryptographic attestation from her local driving authority that attests to her age, date of birth, country of residence and ability to drive.

Alice is able to split up this attestation (see merkle tree attestations ERC here) and provide only the branch that states she is over the age of 21.

Alice goes to buy the wine through the wine vendors smart contract and feeds in the merkle tree attestation proving that she is above 21 and can thus buy the wine, whilst attaching the appropriate amount of ether to complete the purchase.

The wine vendors smart contract validates the attestation, checks the payment amount is correct and credits Alice with the wine tokens she needs to complete the sale and deliver the wine.

### Draft interface and implementation

TODO link
