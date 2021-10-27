package io.alchemynft.attestation;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;

public class CompressedMsgSignature extends AbstractSignature {
  private static final String TYPE_OF_SIGNATURE = "compressed";

  public CompressedMsgSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg) {
    super(keys, unprocessedMsg, TYPE_OF_SIGNATURE);
  }

  public CompressedMsgSignature(byte[] signature) {
    super(signature, TYPE_OF_SIGNATURE);
  }

  @Override
  public byte[] processMessage(byte[] unprocessedMsg) {
    return SignatureUtility.convertToPersonalEthMessage(AttestationCrypto.hashWithKeccak(unprocessedMsg));
  }

}
