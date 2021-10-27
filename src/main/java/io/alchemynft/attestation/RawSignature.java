package io.alchemynft.attestation;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

public class RawSignature extends AbstractSignature {
  private static final String TYPE_OF_SIGNATURE = "raw";

  public RawSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg) {
    super(keys, unprocessedMsg, TYPE_OF_SIGNATURE);
  }

  public RawSignature(byte[] signature) {
    super(signature, TYPE_OF_SIGNATURE);
  }

  @Override
  public byte[] processMessage(byte[] unprocessedMsg) {
    return unprocessedMsg.clone();
  }
}
