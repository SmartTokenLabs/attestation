pragma solidity ^0.4.1;
pragma experimental ABIEncoderV2;
//The purpose of this contract is to manage the list of valid issuer contracts
// and their capacity to fulfil requirements
contract ManagedListERC
{
  //manager is the contract steward, only he/she/it can change/remove/add lists
  //issuer is the contract that handles verification and revocation of an attestation
  //attestation key is the key that signs attestations, note: This is not the issuer address

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
  function getIssuerCorrespondingToAttestationKey(uint list_id, address signingKeyOfAttestation) public returns (address);

   /* for simplicity we use sender's address as the list ID,
     * accepting these consequences: a) if one user wish to maintain
     * several lists with different capacity, he or she must use a
     * different sender address for each. b) if the user replaced the
     * sender's key, either because he or she suspect the key is
     * compromised or that it is lost and reset through special means,
     * then the list is still identified by the first sender's
     * address.
  */
  function addList(List list) public;

  /* replace list manager's key with the new key */
  function replaceListIndex(List list, address manager) public returns(bool);

}

contract ValidationContractInstantiation
{
    //note: this is implemented inside the issuers contract but the method signature is consistent
    //We need to instantiate an empty function to use the compiler to call the function in another contract
    function validate(address attester) public returns(bool) {}
}

contract IssuerListManager is ManagedListERC
{
  //list id is a uint
  mapping(uint => List[]) lists;
  address manager; //manager can remove/change/add lists

  constructor(address managerOfContract) public
  {
      manager = managerOfContract;
  }

  function addIssuer(address issuerContractAddress, uint list_id, uint indexOfList) public
  {
      require(msg.sender == manager);
      lists[list_id][indexOfList].issuerContracts.push(issuerContractAddress);
  }

  function removeIssuer(address issuerContractAddress, uint list_id) public returns(bool)
  {
       require(msg.sender == manager);
       for(uint i = 0; i < lists[list_id].length; i++)
       {
          for(uint j = 0; j < lists[list_id][i].issuerContracts.length; j++)
          {
              if(lists[list_id][i].issuerContracts[j] == issuerContractAddress)
              {
                  delete lists[list_id][i].issuerContracts[j];
                  return true;
              }
          }
       }
       return false;
  }

  function getIssuerCorrespondingToAttestationKey(uint list_id, address signingKeyOfAttestation) public returns (address)
  {
      List[] storage listsToQuery = lists[list_id];
      for(uint i = 0; i < listsToQuery.length; i++)
      {
          for(uint j = 0; j < listsToQuery[i].issuerContracts.length; j++)
          {
               address issuerContract = listsToQuery[i].issuerContracts[j];
               bool isValid = ValidationContractInstantiation(issuerContract).validate(signingKeyOfAttestation);
               if(isValid) return issuerContract;
          }
      }
      return address(0);
  }

  function addList(List list, uint index) public
  {
      require(msg.sender == manager);
      lists[index].push(list);
  }

}
