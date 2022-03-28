package org.tokenscript.attestation.core;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class RawSignature extends AbstractSignature {
  private static final String TYPE_OF_SIGNATURE = "raw";

  public RawSignature(AsymmetricKeyParameter signingKey, byte[] unprocessedMsg) {
    super(signingKey, unprocessedMsg, TYPE_OF_SIGNATURE);
  }

  public RawSignature(byte[] signature) {
    super(signature, TYPE_OF_SIGNATURE);
  }

  @Override
  byte[] processMessage(byte[] unprocessedMsg) {
    return unprocessedMsg.clone();
  }
}
