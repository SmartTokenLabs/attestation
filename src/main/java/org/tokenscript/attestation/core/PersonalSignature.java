package org.tokenscript.attestation.core;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class PersonalSignature extends AbstractSignature {
  private static final String TYPE_OF_SIGNATURE = "personal";

  public PersonalSignature(AsymmetricKeyParameter signingKey, byte[] unprocessedMsg) {
    super(signingKey, unprocessedMsg, TYPE_OF_SIGNATURE);
  }

  public PersonalSignature(byte[] rawSignature) {
    super(rawSignature, TYPE_OF_SIGNATURE);
  }

  @Override
  byte[] processMessage(byte[] unprocessedMsg) {
    return SignatureUtility.convertToPersonalEthMessage(unprocessedMsg);
  }

}
