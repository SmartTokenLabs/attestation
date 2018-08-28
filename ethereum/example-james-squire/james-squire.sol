/* A demonstration of how to use attestation in validating customers'
 * purchase. The contract assumes the scenario of alcohol purchase
 * from a vendor James Squire. The contract will be satisfied if the
 * buyer can prove that his residential country is Australia and the
 * buyer's age is above 18. It, however, allows the contract's owner
 * to extend to allow consumers from other countries, and in the case
 * the said country doesn't have an age restriction on drinking, for
 * example China, the contract should only requires a proof of
 * residency in China.*/

import "../lib/AttestationFramework";
import "../lib/AuthorisedAttestors";

contract james-squire is AttestationFramework, AuthorisedAttestors
{

    AttestationFramework attestationFramework;
    AuthorisedAttestors authorisedAttestors;
    string[] ageExemptCountries;

    constructor(
      address attestationFrameworkAddress,
      address authorisedAttestorsAddress,
      string[] ageExemptAndAcceptedCountries
    )
    {
        attestationFramework = new AttestationFramework(attestationFrameworkAddress);
        authorisedAttestors = new AuthorisedAttestors(authorisedAttestorsAddress);
        ageExemptCountries = ageExemptAndAcceptedCountries;
    }

    function canPurchaseAlcohol(Attestation ageAttestation) public returns (bool)
    {
        require(attestationFramework.validateMerkle(ageAttestation));
        bool isExempt = isAgeExemptAndAcceptedCountry(ageAttestation.value);
        if(isExempt) return true;
        //TODO probably need multiple branches?
        //if(ageAttestation.age >= 18) return true;
        return false;
    }

    function isAgeExemptAndAcceptedCountry(string country) public returns (bool)
    {
        for(uint i = 0; i < ageExemptAndAcceptedCountries.length; i++)
        {
            if(country == ageExemptAndAcceptedCountries[i]) return true;
        }
        return false;
    }
}
