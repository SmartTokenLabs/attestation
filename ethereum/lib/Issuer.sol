pragma solidity ^0.4.17;
import "./MerkleTreeAttestation"; // to get Attestation struct
import "../trustlist/ManagedList"; // to manage the list run by the issuers

/* each attestation issuer should provide their own verify() for the
 * attestations they issued. There are two reasons for this. First, we
 * need to leave room for new attestation methods other than the
 * Merkle Tree format we are recommending. Second, the validity of the
 * attestation may depend on the context that only the attester
 * knows. For example, a ticket as an attestation issued on a
 * successful redemption of an American Express credit */
contract Issuer {
  /* Verify the authenticity of an attestation */
  function verify(Attestation attestation);
  //note: adding, changing and revoking attestations and attestor keys requires a contract manager
  function addAttestorKey(address newAttestor, string capacity, uint expiry);

  /* this should call the revoke first */
  function replaceKey(address attestorToReplace, string capacity, uint expiry, address newAttestor);

  /* this revokes a single key */
  function removeKey(address attestor);

  /* if the key exists with such capacity and isn't revoked or expired */
  function validateKey(address attestor, string capacity) returns (bool);

  /* revoke an attestation by replace the bloom filter, this helps preserve privacy */
  function revokeAttestations(Bloomfilter b);

}
