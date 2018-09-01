pragma solidity ^0.4.17;
import "./AttestationFramework";

/* each attestation issuer should maintain their way to validate the
 * attestations they issued. There are two reasons for that. First, we
 * need to leave room for new attestation methods other than the
 * Merkle Tree format we recommending. Second, the validity of the
 * attestation may depends on context that only the attester
 * knows. For example, a ticket as an attestation issued on a
 * successful redemption of American Express credit */
contract Issuer {

  /* the sender's key is not relevant here */
  function addKey(address key_id, bytes capacity, uint expiry);
  
  /* this should call the revoke first */
  function addKey(address key_id, bytes capacity, uint expiry, address replaced_key_id);

  /* this revokes a single key */
  function revokeKey(address key_id);

  /* if the key exists with such capacity and isn't revoked or expired */
  function validateKey(address key_id, bytes capacity) return (boolean);

  function validateAttestation(attestation);
}
