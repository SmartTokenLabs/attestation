package io.alchemynft.attestation;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.tokenscript.attestation.core.SignatureUtility;

public class PersonalSignature extends AbstractSignature {
  private static final String TYPE_OF_SIGNATURE = "personal";

  public PersonalSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg) {
    super(keys, unprocessedMsg, TYPE_OF_SIGNATURE);
  }

  public PersonalSignature(byte[] rawSignature) {
    super(rawSignature, TYPE_OF_SIGNATURE);
  }

  @Override
  byte[] processMessage(byte[] unprocessedMsg) {
    return SignatureUtility.convertToPersonalEthMessage(unprocessedMsg);
  }

}
