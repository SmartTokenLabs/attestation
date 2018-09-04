pragma solidity ^0.4.1;
pragma experimental ABIEncoderV2;
contract ManagedListERC
{

  struct List
  {
    string name;
    string description;
    string capacity;
    address[] issuers;
    uint expiry;
  }

   // find which list the sender is managing, then add an issuer to it
  function addIssuer(address contractAddress) public;

  //return false if the list identified by the sender doesn't have this issuer in the list
  function removeIssuer(address contractAddress, List listToRemoveIssuerFrom) public returns(bool);

    //TODO this is very unclear
  /* called by services, e.g. Kiwi Properties or James Squire */
  /* loop through all issuer's contract and execute validateKey() on
   * every one of them in the hope of getting a hit, return the
   * contract address of the first hit. Note that there is an attack
   * method for one issuer to claim to own the key of another which
   * is mitigated by later design. */
  function getIssuerByKey(address issuer, address key_id_to_validate) public returns (address);

    //TODO why not map to an array?
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
  function replaceListKey(List list, address key) public returns(bool);

}

contract IssuerListManager is ManagedListERC
{

  mapping(address => List[]) lists;

  function addIssuer(address contractAddress, uint indexOfList) public
  {
      lists[msg.sender][indexOfList].issuers.push(contractAddress);
  }

  function removeIssuer(address contractAddress, List listToRemoveIssuerFrom) public returns(bool)
  {
      for(uint i = 0; i < listToRemoveIssuerFrom.issuers.length; i++)
      {
          if(listToRemoveIssuerFrom.issuers[i] == contractAddress)
          {

          }
      }
  }

  function getListIndex(address holder, List listToCheck) returns(uint)
  {
      for(uint i = 0; i < lists[holder].length; i++)
      {
          //if(lists[holder][i] == listToCheck) return i;
      }
      throw;
  }

  //TODO unclear
  function getIssuerByKey(address issuer, address key_id_to_validate) public returns (address)
  {
      for(uint i = 0; i < lists[key_id_to_validate].length; i++)
      {
          for(uint j = 0; j < lists[key_id_to_validate][i].issuers.length; j++)
          {
              if(lists[key_id_to_validate][i].issuers[j] == issuer)
              {
                 return issuer;
              }
          }
      }
  }

  function addList(List list) public
  {
      lists[msg.sender].push(list);
  }

  function replaceListKey(List list, address key) public returns(bool)
  {
    //   for(uint i = 0 ; i < lists[msg.sender].length; i++)
    //   {
    //       if(lists[msg.sender][i] == list)
    //       {
    //           lists[key].push(lists[msg.sender][i]);
    //           delete lists[msg.sender][i];
    //           return true;
    //       }
    //   }
    //   return false;
  }

}
