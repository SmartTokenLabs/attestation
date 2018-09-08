pragma solidity ^0.4.17;
import "./Issuer";
import "../lib/AttestationFramework"; // to get BloomFilter

contract issuerA is Issuer {

    address issuer;
    mapping (address => string) attestationSigningKeysAndCapacity;
    mapping (address => uint) attestationKeyExpiry;

    constructor(address issuerForContract)
    {
        issuer = issuerForContract;
    }

    function verify(Attestation a)
    {
        /* THIS FUNCTION IS SUPPOSED TO BE CALLED FROM ANOTHER SMART CONTRACT, MOSTLY */
    	// 1. the attestation is not revoked // usually, check the bloom filter
    	// 2. the attestation is not expired
    	// 3. the attestation is signed by one of the current issuer's keys
      // 4. the sender is the attestation's owner
    	// 5. the issuer's key has not expired
      // 6. the merkle tree is well formed and the siganture on the tree is valid
    	require(attestationFramework.validateMerkle(ageAttestation));
    	// 7. any custom logic by the issuer (e.g. do not acknowledge
    	// any attestation issued before 2018-12-01 because they are
    	// all issued by a corrupt communist official
    }

    function addAttestationSigningKey(address newattester, string capacity, uint expiry)
    {
       require(msg.sender == issuer);
	     // keep it in the states
       attestationSigningKeysAndCapacity[newattester] = capacity;
       attestationKeyExpiry[newattester] = expiry;
     }

    function replaceAttestationSigningKey(address attesterToReplace, string capacity, uint expiry, address newattester)
    {
      require(msg.sender == issuer);
      delete attestationSigningKeysAndCapacity[attesterToReplace];
      delete attestationKeyExpiry[attesterToReplace];
      attestationSigningKeysAndCapacity[newattester] = capacity;
      attestationKeyExpiry[newattester] = expiry;
    }

    function removeAttestationSigningKey(address attester)
    {
      require(msg.sender == issuer);
      delete attestationSigningKeysAndCapacity[attester];
      delete attestationKeyExpiry[attester];
    }

    /* attestations are revoked in bulk by Bloomfilters of revoked
     * attestations' hashes. Notice that this function is not required
     * by the Issuer interface - it is up to the issuer to decide if
     * they use Bloomfilter for revocation */
    function revokeAttestations(Bloomfilter b) { // only issuer can do this
  	//all bloom filters are stored in the contract variable space

	/* there are typically 2 strategies to use bloom
	 * filters. Ether the contract maintains a list of bloom
	 * filters in its state varaibles - any attestation marked by
	 * any of them is considered revoked; or the contract
	 * maintains only a single bloom filter - each time this
	 * function is called, the new bloom filter replaces the old
	 * one. The best strategy varies by issuers*/

	/* IMPLEMENTATION NOTE: in an issuer organisation where each
	 * attestation signing key owner have the privilege to revoke
	 * the attestation it signed, this function can be called from
	 * an Ethereum address corrisponding to the attestation
	 * key. */
    }

}
