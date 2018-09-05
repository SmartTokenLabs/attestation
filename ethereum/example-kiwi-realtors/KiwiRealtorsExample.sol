import "../lib/MerkleTreeAttestation";
import "../lib/AttestationUsing";
import "../trustlist/ManagedList";

/*
  Buying property in New Zealand requires the buyer
  to be a PR/Citizen of ether New Zealand or Australia
  This example contract acts as an agent and allows potential customers
  to validate their ability to purchase property
*/

contract KiwiRealtorsExample is AttestationUsing {

    AttestationFramework attestationFramework;
    string[] ageExemptCountries;
    ManagedList managedList;
    address list_id; /* trusted list */
    string capacity = "Notarised";
    ManagedList managedList;
    string predicate;
    uint list_id;

    constructor(
      address attestationFrameworkAddress,
      string[] ageExemptAndAcceptedCountries,
      address managedListAddress
    )
    {
        attestationFramework = AttestationFramework(attestationFrameworkAddress);
        predicate = '(|(c=NZ)(c=AU))';
        /* permanent residency and citizenship attester list example*/
        list_id = 0xdecafbad0000;
        /* supposedly the deployed address of the ManagedList contract */
        managedList = ManagedList(managedListAddress);
    }

    function canPurchaseProperty(AttestationUsing.Attestation attestation) public returns (bool)
    {
      address issuerKeyID = ecrecover(attestation.hash, attestation.r, attestation.s, attestation.v);

      /* issuerListContract is a predefined central registery of a)
       * list manager's key; b) list's delication mechanism; c) *
       * list's description (the verb) */

      address issuerContract = managedList.getIssuerByKey(list_id, issuerKeyID, capacity);
      require(issuerContract != address(0));
      Issuer issuer = Issuer(issuerContract);
      require(issuer.validateAttestation(attestation)); /* FIXME: return false otherwise */

      /* the following line delicates the call to the issuer's own
       * contract, which is issuer/example_issuer.sol's verify(). It
       * refuses to act if the attestation is not signed by a member
       * of the issuerList */
      return AttestationFramework.evaluate(predicate, attestation.key, attestation.value);
    }

    function ExpressOfInterest(AttestationUsing.Attestation attestation,
      uint property_id,
      uint priceRangeLow,
      uint priceRangeHigh) {
      require(canPurchaseProperty(attestation));

      /* your business logic goes here, e.g. how many ethers are
	 needed to express interest */
    }

    /* required by AttestationUsing */
    function getAttestationPredicate(bytes4 functionSignature) returns (string){
      /* We ignore function signature here because we only have 1
	 function which requires attestation*/
      return predicate;
    }

    function getIssuerList() public returns (List)
    {
        return managedList.getListById(list_id);
    }
}
