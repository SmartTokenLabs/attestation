package io.alchemynft.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface Signature {
  public byte[] getRawSignature();

  public String getTypeOfSignature();

  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey);
}
