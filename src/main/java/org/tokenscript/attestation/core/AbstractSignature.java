package org.tokenscript.attestation.core;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class AbstractSignature implements Signature {
  private final String type;
  private final byte[] rawSignature;

  public AbstractSignature(AsymmetricKeyParameter signingKey, byte[] unprocessedMessage, String type) {
    this.type = type;
    this.rawSignature = sign(signingKey, unprocessedMessage);
  }

  public AbstractSignature(byte[] rawSignature, String type) {
    this.type = type;
    this.rawSignature = rawSignature;
  }

  protected byte[] sign(AsymmetricKeyParameter keys, byte[] unprocessedMessage) {
    return SignatureUtility.signWithEthereum(processMessage(unprocessedMessage), keys);
  }

  @Override
  public byte[] getRawSignature() {
    return rawSignature;
  }

  @Override
  public String getTypeOfSignature() {
    return type;
  }

  /**
   * Processes any message and returns the raw bytes that are actually being signed
   * @return
   */
  abstract byte[] processMessage(byte[] unprocessedMsg);

  @Override
  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey) {
    return SignatureUtility.verifyEthereumSignature(processMessage(unprocessedMsg), rawSignature, verificationKey);
  }

}
