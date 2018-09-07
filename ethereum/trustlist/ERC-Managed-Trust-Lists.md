## Draft ERC - Managing lists for trusted smart contract identifiers  

### Introduction

In smart contracts, we will need methods to handle cryptographic attestations to a users identifier or abilities. Let's say we have a real estate agent, KiwiRealtors, that provides an "expression of interest" function though a smart contract and requires the users to provide an attestation that they are resident of New Zealand or Australia, as a legal requirement. This has actually happened in the New Zealand property market and it is the perfect example of a need to handle such attestations.

However, it is not practical for a smart contract to explicitly trust an attestation issuer. There are multiple issuers who can provide an attestation on a person's residency - a local Justice of the Peace, the land title office, local police, passport authority etc. We envision a model where the effort to manage the list of qualified issuers is practically outsourced to a list.

Anyone can publish a list of issuers. Only the most trusted and carefully maintained lists gets popular use.

### Purpose
This ERC provides a smart contract interface for anyone to manage a list of attestation issuers. A smart contract would explicitly trust a list, and therefore all attestations issued by the issuers on the list.

### Draft implementation
`contract ManagedListERC
{
  //manager is the contract steward, only he/she/it can change/remove/add lists
  //issuer is the contract that handles verification and revocation of an attestation
  //attestation key is the key that signs attestations, note: This is not the issuer address and since issuers
  //are contracts, there is no way for an issuer to sign anything.

  struct List
  {
    string name;
    string description; //short description of what the list entails
    string capacity; //capacity is the specification of the keys authority
    //e.g. school id card vs passport
    //one has the capacity to buy alcohol, the other does not.
    address[] issuerContracts; //all these addresses are contracts, no signing capacity
    uint expiry;
  }

   // find which list the sender is managing, then add an issuer to it
  function addIssuer(address issuerContractAddress) public;

  //return false if the list identified by the sender doesn't have this issuer in the list
  function removeIssuer(address issuerContractAddress, List listToRemoveIssuerFrom) public returns(bool);

  /* called by services, e.g. Kiwi Properties or James Squire */
  /* loop through all issuer's contract and execute validateKey() on
   * every one of them in the hope of getting a hit, return the
   * contract address of the first hit. Note that there is an attack
   * method for one issuer to claim to own the key of another which
   * is mitigated by later design. */
   //loop through the issuers array, calling validate on the signingKeyOfAttestation
  function getIssuerCorrespondingToAttestationKey(bytes32 list_id, address signingKeyOfAttestation) public returns (address);

   /* for simplicity we use sender's address as the list ID,
     * accepting these consequences: a) if one user wish to maintain
     * several lists with different capacity, he or she must use a
     * different sender address for each. b) if the user replaced the
     * sender's key, either because he or she suspect the key is
     * compromised or that it is lost and reset through special means,
     * then the list is still identified by the first sender's
     * address.
  */

  function createList(List list) public;

  /* replace list manager's key with the new key */
  function replaceListIndex(List list, address manager) public returns(bool);

}`

Click [here](https://github.com/alpha-wallet/blockchain-attestation/blob/master/ethereum/trustlist/ManagedList.sol) to see an example implementation of this ERC
