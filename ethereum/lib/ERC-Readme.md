## ERC - Merkle Tree Attestations

### Introduction & Purpose

With blockchains like Ethereum, we are able to validate identifiers which attest
to a users identity or credentials. In this ERC, we outline a way to do so using
a Merkle tree structure which allows anyone to efficiently validate themselves
in a privacy enabled fashion.

Please note that these attestations are issued off chain and when used on chain
they only require the relevant leaf nodes to be revealed.

For example, if Alice wanted to buy beer tokens which can be redeemable for beer
at the liquor store, she can provide the leaf of the merkle tree which states
she is above 21.

### Draft implementation
`contract MerkleTreeAttestationInterface {
    struct Attestation
    {
        bytes32[] merklePath;
        bool valid;
        uint8 v;
        bytes32 r;
        bytes32 s;
        address attestor;
        address recipient;
        bytes32 salt;
        bytes32 key;
        bytes32 val;
    }

    function validate(Attestation attestation) public returns(bool);
}`

### relevant implementation examples
[Here](https://github.com/alpha-wallet/blockchain-attestation/blob/master/ethereum/lib/MerkleTreeAttestation.sol) is an example implementation of the MerkleTreeAttestationInterface
[Here](https://github.com/alpha-wallet/blockchain-attestation/blob/master/ethereum/example-james-squire/james-squire.sol) is an example service which would use such a merkle tree attestation
