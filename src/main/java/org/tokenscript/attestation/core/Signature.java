package org.tokenscript.attestation.core;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface Signature {
  public byte[] getRawSignature();

  public String getTypeOfSignature();

  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey);
}
