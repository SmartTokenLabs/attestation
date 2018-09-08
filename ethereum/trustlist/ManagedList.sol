pragma solidity ^0.4.1;
pragma experimental ABIEncoderV2;
import "../lib/Issuer"; //we import the issuer for validating an attesters key

/* The purpose of this contract is to manage the list of attestation
 * issuer contracts and their capacity to fulfil requirements
 */
contract ManagedListERC
{
  /* a manager is the steward of a list. Only he/she/it can change the
   * list by removing/adding attestation issuers to the list.

   * A issuer in the list is represented by his/her/it contract
   * addresses, not by the attestation signing keys managed by such a
   * contract.
   */
  struct List
  {
    string name;
    string description; // short description of what the list entails
    string capacity; // serves as a filter for the attestation signing keys
      /* if a smart contract spcifies a list, only attestation issued
       * by issuers on that list is accepted. Furthermore, if that
       * list has a non-empty capacity, only attestations signed by a
       * signing key with that capacity is accepted. */

    address[] issuerContracts; // all these addresses are contracts,
			       // no signing capacity
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
     * sender's key, either becauyse he or she suspect the key is
     * compromised or that it is lost and reset through special means,
     * then the list is still identified by the first sender's
     * address.
  */

  function createList(List list) public;

  /* replace list manager's key with the new key */
  function replaceListIndex(List list, address manager) public returns(bool);

}

contract IssuerListManager is ManagedListERC
{
  //list id is a uint
  mapping(bytes32 => List[]) lists;
  Issuer issuer;
  address manager; //manager can remove/change/add lists

  constructor(address managerOfContract) public
  {
      manager = managerOfContract;
  }

  function addIssuer(address issuerContractAddress, bytes32 list_id, uint indexOfList) public
  {
      require(msg.sender == manager);
      lists[list_id][indexOfList].issuerContracts.push(issuerContractAddress);
  }

  function removeIssuer(address issuerContractAddress, bytes32 list_id) public returns(bool)
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

  function getIssuerCorrespondingToAttestationKey(
    bytes32 list_id,
    address signingKeyOfAttestation
  ) public returns (address)
  {
      List[] storage listsToQuery = lists[list_id];
      for(uint i = 0; i < listsToQuery.length; i++)
      {
          for(uint j = 0; j < listsToQuery[i].issuerContracts.length; j++)
          {
               address issuerContract = listsToQuery[i].issuerContracts[j];
               /* if the key exists with such capacity and isn't revoked or expired, from Issuer.sol */
               //function validateKey(address attester, string capacity) returns (bool);
               bool isValid = Issuer(issuerContract).validateKey(signingKeyOfAttestation, listsToQuery[i].capacity);
               if(isValid) return issuerContract;
          }
      }
      return address(0);
  }
  //hash address plus block.timestamp + name
  function createList(List list) public
  {
      require(msg.sender == manager);
      bytes32 list_id = keccak256(abi.encodePacked(msg.sender, block.timestamp, list.name));
      lists[list_id].push(list);
  }

}
