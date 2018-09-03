contract ManagedList {
    /* called by list managers: add an issuer to the list identified by
     the sender's address */

  struct List {
      address[] issuer;
  }

  List lists;

   // find which list the sender is managing, then add an issuer to it
  function addIssuer(address contractAddress);
  //throw if the list identified by the sender doesn't have this issuer in the list
  function removeIssuer(address contractAddress);

  /* called by services, e.g. Kiwi Properties or James Squire */
  /* loop through all issuer's contract and execute validateKey() on
   * every one of them in the hope of getting a hit, return the
   * contract address of the first hit. Note that there is an attack
   * method for one issuer to claim to own the key of another which
   * is mitigated by later design. */
  function getIssuerByKey(address[] list, address key_id, bytes capacity) returns (address);

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
    //require(lists[sender] != address(0));
    //lists[sender] = new List<address>;
  }

  function replaceListKey(string name, address key) {
    /* replace list manager's key with the new key */
  }

}
