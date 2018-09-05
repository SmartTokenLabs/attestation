/* Interface for all contracts which uses attestation */
//TODO better to not use function signatures as they require static calling,
//better to simply call the contract with instantiation
contract AttestationUsing {
  function getAttestationPredicate(bytes4 functionSignature) returns (string);
  function getIssuerList(bytes4 functionSignature) returns (address);
}
