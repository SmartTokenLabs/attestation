/* Interface for all contracts which uses attestation */

contract AttestationUsing {
  function getAttestationPredicate(bytes4 functionSignature) returns (string);
  function getIssuerList(bytes4 functionSignature) returns (address);
}
