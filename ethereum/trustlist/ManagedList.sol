
contract ManagedList {
  List lists;
  
  /* called by list managers */
  function addIssuer(address contract);
  {
    /* find which list the sender is managing, then add an issuer to
       it */
  }
  function removeIssuer(address contract)
  {
  }

  /* called by services, e.g. Kiwi Properties or James Squire */
  function getIssuerByKey(address list, address key_id, bytes capacity) return (address contract) {
  /* loop through all issuer's contract and execute validateKey() on
   * every one of them in the hope of getting a hit, return the
   * contract address of the first hit. Note that there is an attack
   * method for one issuer to claim to own the key of another which
   * is mitigated by later design. */
  }
  
  function addList(string name, string description, string capacity) {
    /* for simplicity we use sender's address as the list ID,
     * accepting these consequences: a) if one user wish to maintain
     * several lists with different capacity, he or she must use a
     * different sender address for each. b) if the user replaced the
     * sender's key, either because he or she suspect the key is
     * compromised or that it is lost and reset through special means,
     * then the list is still identified by the first sender's
     * address.
     */
    // FIXME these are pseudo code
    if (lists[sender]) throws;
    else lists[sender] = new List<address>;
  }

  function replaceListKey(name, address key) {
    /* replace list manager's key with the new key */
  }

}
