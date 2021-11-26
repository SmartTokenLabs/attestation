package io.alchemynft.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CheckableObject;

public interface SignedNFTAttestation extends CheckableObject {
  AsymmetricKeyParameter getNFTAttestationVerificationKey();
  NFTAttestation getUnsignedAttestation();
}
