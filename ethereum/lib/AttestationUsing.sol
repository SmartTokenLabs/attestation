/* Interface for all contracts which uses attestation */

contract AttestationUsing {
  function getAttestationPredicate(byte4 functionSignature) return (string);
  function getIssuerList(byte4 functionSignature) return (address)
}
