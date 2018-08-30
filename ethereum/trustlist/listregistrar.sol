
contract list_management {

	function new_list(name, description, key_policy) {
		/* for simplicity, we assume the list is identified by the hash of its name */
		sender's key should be stored in state variables
	}

	function list_replace_key(name, address key) {
		replace list manager's key with the new key
	}

	function addIssuer(key, address) { /* address is the issuer's contract address, a mapping needs to be maintained */
        function removeIssuer()
        function verify(list_id, attestation) {
		/* 1. restore signer's key from attestation.r; attestation.s; attestation.v */
		/* 2. check if the key is in the list */
		/* 3. deligate the call to the issuer's contract's verify() */
	}
}
