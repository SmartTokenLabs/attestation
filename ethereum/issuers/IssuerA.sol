pragma solidity ^0.4.17;
import "../lib/Issuer";
import "../lib/AttestationFramework"; // to get BloomFilter
import "../trustlist/ManagedList";

contract issuerA is Issuer {

    ManagedList managedList;

    constructor(address managedListAddress)
    {
        managedList = ManagedList(managedListAddress);
    }

    function verify(attestation a) {
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
    //TODO authorised to do this?
    function addKey(uint key_id, List newList) {
	     // keep it in the states
       managedList.addList(key_id, newList);
    }

    //TODO fix naming and make more clear as to what this actual is
    function addKey(address key_id, string capacity, uint expiry, address replaced_key_id) {
    }

    //TODO delete listing?
    function removeKey(address key_id) {
    }
    //TODO handle bloom filters in solidity and prevent spaming it for false positives
    function revoke(Bloomfilter b) {
  	//all bloom filters are stored in the contract variable space
    /* attestations are revoked in bulk by Bloomfilters. Notice
  	 * that this function is not required by the Issuer interface
  	 * - it is up to the issuer to decide if they use Bloomfilter
  	 * for revocation */
    }

}
