import "../lib/AttestationFramework";
import "../lib/AuthorisedAttestors";

/* propoerty purchase in New Zealand requires buyer having permanent
 * residency of New Zealand or Australia or .....  to simplify the
 * case, kiwi property is an agent. The customers are potential
 * property buyers and property deed is not issued on the blockchain
 * in this example.
*/
contract kiwi_property is AttestationFramework, AuthorisedAttestors
{

    AttestationFramework attestationFramework;
    string[] ageExemptCountries;

    constructor(
      address attestationFrameworkAddress,
      address authorisedAttestorsAddress,
      string[] ageExemptAndAcceptedCountries
    )
    {
        attestationFramework = new AttestationFramework(attestationFrameworkAddress);
        authorisedAttestors = new AuthorisedAttestors(authorisedAttestorsAddress);
        predicate = '(|(c=NZ)(c=AU))'
	issuerList = 0xdecafbad00..00; /* Permant residency and citizenship attester list */
    }

    function canPurchaseProperty(Attestation attestation) public returns (bool)
    {
	/* issuerListContract is a predefined central registery of
	 * a) list manager's key; b) list's delication mechanism; c)
	 * list's description (the verb) */

	/* the following line delicates the call to the authorit's own
	 * contract, which is issuer/example_issuer.sol's verify(). It
	 * refuses to act if the attestation is not signed by a member
	 * of the issuerList */
	issuerListContract.verify(issuerList, attestation);
        AttestationFramework.evaluate(predicate, attestation.key, attestation.value);
    }

    function ExpressOfInterest(attestation, property_id, priceRangeLow, priceRangeHigh) {
	require(canPurchaseProperty(attestation));
	... /* your business logic goes here */
    }
}
