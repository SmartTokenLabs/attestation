import "../lib/MerkleTreeAttestation";
import "../lib/AttestationUsing";
import "../trustlist/ManagedList";

/*
  Buying property in New Zealand requires the buyer
  to be a PR/Citizen of either New Zealand or Australia
  This example contract acts as an agent and allows potential customers
  to validate their ability to purchase property
*/

contract KiwiRealtorsExample is AttestationUsing {

    AttestationFramework attestationFramework;
    string[] ageExemptCountries;
    ManagedList managedList;
    bytes32 list_id; /* trusted list */
    string capacity = "Notarised";
    ManagedList managedList;
    string[] predicateFunctionSignatures;
    mapping (string => string) predicates; //map predicates to their function signatures
    string predicateExample = '(|(c=NZ)(c=AU))';

    constructor(
      address attestationFrameworkAddress,
      string[] ageExemptAndAcceptedCountries,
      address managedListAddress,
      string[] predicateFuncs,
      string[] predicates,
      string listName
    )
    {
        attestationFramework = AttestationFramework(attestationFrameworkAddress);
        /* permanent residency and citizenship attester list example*/
        list_id = keccak256(abi.encodePacked(msg.sender, block.timestamp, listName));
        /* supposedly the deployed address of the ManagedList contract */
        managedList = ManagedList(managedListAddress);
        predicateFunctionSignatures = predicateFuncs;
        for(uint i = 0; i < predicateFunctionSignatures.length; i++)
        {
            predicates[predicateFunctionSignatures[i]] = predicates[i];
        }
    }

    function canPurchaseProperty(AttestationUsing.Attestation attestation) public returns (bool)
    {
      address attestationSigningKey = ecrecover(attestation.hash, attestation.r, attestation.s, attestation.v);

      /* issuerListContract is a predefined central registery of a)
       * list manager's key; b) list's delication mechanism; c) *
       * list's description (the verb) */
      Issuer issuer = Issuer(attestation.issuerContract);

      require(issuer.validateAttestation(attestation));

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
    //help the user agent/wallet know
    //what to give when needing a function that requires a custom predicate
    //this is only supposed to be a call not a tx
    function getAttestationPredicate(bytes4 functionSignature) returns (string)
    {
      //in this example we only have one predicate
      //if there is no corresponding predicate, the agent will recieve a null string
      return predicates[functionSignature];
    }

    function getIssuerList() public returns (List)
    {
        return managedList.getListById(list_id);
    }
}
