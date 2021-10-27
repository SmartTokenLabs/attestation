package io.alchemynft.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface Signature {
  public byte[] getRawSignature();

  public String getTypeOfSignature();

  /**
   * Processes any message and returns the raw bytes that are actually being signed
   * @return
   */
  public byte[] processMessage(byte[] unprocessedMsg);

  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey);
}
