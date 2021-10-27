package io.alchemynft.attestation;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.SignatureUtility;

public abstract class AbstractSignature implements Signature {
  private final String type;
  private final byte[] rawSignature;

  public AbstractSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMessage, String type) {
    this.type = type;
    this.rawSignature = sign(keys, unprocessedMessage);
  }

  protected byte[] sign(AsymmetricCipherKeyPair keys, byte[] unprocessedMessage) {
    return SignatureUtility.signWithEthereum(processMessage(unprocessedMessage), keys.getPrivate());
  }

  @Override
  public byte[] getRawSignature() {
    return rawSignature;
  }

  @Override
  public String getTypeOfSignature() {
    return type;
  }

  @Override
  public abstract byte[] processMessage(byte[] unprocessedMsg);

  @Override
  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey) {
    return SignatureUtility.verifyEthereumSignature(processMessage(unprocessedMsg), rawSignature, verificationKey);
  }

}
