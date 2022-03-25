package io.alchemynft.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CheckableObject;

public interface InternalSignedNFTAttestation extends CheckableObject {
  AsymmetricKeyParameter getNFTAttestationVerificationKey();
  NFTAttestation getUnsignedAttestation();
  int getSigningVersion();
  byte[] getRawSignature();
}

