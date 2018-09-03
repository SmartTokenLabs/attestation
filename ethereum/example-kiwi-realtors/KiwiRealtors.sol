import "../lib/MerkleTreeAttestation";
import "../lib/AttestationUsing";

/* propoerty purchase in New Zealand requires buyer having permanent
 * residency of New Zealand or Australia or .....  to simplify the
 * case, kiwi property is an agent. The customers are potential
 * property buyers and property deed is not issued on the blockchain
 * in this example.
*/
contract KiwiRealtors is AttestationUsing {

    AttestationFramework attestationFramework;
    string[] ageExemptCountries;
    ManagedList managedList;
    address list_id; /* trusted list */
    string capacity = "Notarised";

    constructor(
      address attestationFrameworkAddress,
      string[] ageExemptAndAcceptedCountries
    )
    {
        attestationFramework = new AttestationFramework(attestationFrameworkAddress);
        predicate = '(|(c=NZ)(c=AU))';
        /* Permant residency and citizenship attester list */
	list_id = 0xdecafbad00..00;
        /* supposedly the deployed address of the ManagedList contract */
        managedList = ManagedList("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae");
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

    function getIssuerList(bytes4 functionSingature) returns (address) {
      return list_add;
    }
}
