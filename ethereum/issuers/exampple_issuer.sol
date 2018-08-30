

contract issuerA {

    function verify(attestation a) {
        /* THIS FUNCTION IS SUPPOSED TO BE CALLED FROM ANOTHER SMART CONTRACT, MOSTLY */
	// 1. the attestation is not revoked
	// 2. the attestation is not expired
	// 3. the attestation is signed by oen of the current issuer's keys
	// 4. the issuer's key has not expired
        // 5. the merkle tree is well formed and the siganture on the tree is valid
	require(attestationFramework.validateMerkle(ageAttestation));

	// 6. any custom logic by the issuer (e.g. do not acknowledge
	// any attestation issued before 2018-12-01 because they are
	// all issued by a corrupt communism official
    }

    function revoke(bloomfilter b) {
	// all bloom filters are stored in the contract variable space
    }

    function getCurrentIdentifyingKeys() {
	// return a list of current identifying keys
    }

    function addKeys(address key, date expiration) {
	// keep it in the states
    }
    
    function removeKeys(address key) {
	// keep it in the states
    }
}
