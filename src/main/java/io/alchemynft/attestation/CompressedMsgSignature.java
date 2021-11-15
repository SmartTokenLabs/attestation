package io.alchemynft.attestation;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;

public class CompressedMsgSignature implements Signature {
  private static final String TYPE_OF_SIGNATURE = "compressed";
  private final byte[] rawSignature;
  private final String messagePrefix;
  private final String messagePostfix;

  public CompressedMsgSignature(byte[] rawSignature) {
    this(rawSignature, "", "");
  }

  public CompressedMsgSignature(byte[] rawSignature, String messagePrefix, String messagePostfix) {
    this.messagePrefix = messagePrefix;
    this.messagePostfix = messagePostfix;
    this.rawSignature = rawSignature;
  }

  public CompressedMsgSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg) {
    this(keys, unprocessedMsg, "", "");
  }

  /**
   * Constructs a compressed signature of the format @messagePrefix concatenated with Keccak(@unprocessedMsg) concatenated with @messagePostfix.
   */
  public CompressedMsgSignature(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg, String messagePrefix, String messagePostfix) {
    this.messagePrefix = messagePrefix;
    this.messagePostfix = messagePostfix;
    this.rawSignature = sign(keys, unprocessedMsg);
  }

  protected byte[] sign(AsymmetricCipherKeyPair keys, byte[] unprocessedMsg) {
    return SignatureUtility.signWithEthereum(processMessage(unprocessedMsg), keys.getPrivate());
  }

  @Override
  public byte[] getRawSignature() {
    return rawSignature;
  }

  @Override
  public String getTypeOfSignature() {
    return TYPE_OF_SIGNATURE;
  }

  byte[] processMessage(byte[] unprocessedMsg) {
    byte[] hashedUnprocessedMsg = AttestationCrypto.hashWithKeccak(unprocessedMsg);
    String hexEncodedHashedMsg = "0x" + Hex.toHexString(hashedUnprocessedMsg).toUpperCase();
    String stringMsgToSign =  messagePrefix + hexEncodedHashedMsg + messagePostfix;
    return stringMsgToSign.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public boolean verify(byte[] unprocessedMsg, AsymmetricKeyParameter verificationKey) {
    return SignatureUtility.verifyEthereumSignature(processMessage(unprocessedMsg), rawSignature, verificationKey);
  }
}
