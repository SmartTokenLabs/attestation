package io.alchemynft.attestation;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.CompressedMsgSignature;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.PersonalSignature;
import org.tokenscript.attestation.core.Signature;

/**
 * Wrapper class to ensure legacy API compatibility of signed NFT attestations.
 */
public class SignedNFTAttestation implements InternalSignedNFTAttestation {
  private static final Logger logger = LogManager.getLogger(SignedNFTAttestation.class);
  public static final String PREFIX_MSG = "The digest of the ERC721 tokens for AlchemyNFT is: ";
  public static final String POSTFIX_MSG = "";

  private final InternalSignedNFTAttestation internalNftAtt;

  /**
   * Constructor ONLY for version 1 signatures
   * @param nftAtt Unsigned NFT attestation
   * @param pk Legacy parameter, which will be ignored
   * @param rawPersonalSignature raw bytes of the signature
   */
  @Deprecated
  public SignedNFTAttestation(NFTAttestation nftAtt,
      AsymmetricKeyParameter pk, byte[] rawPersonalSignature) {
    this(nftAtt, new PersonalSignature(rawPersonalSignature));
  }

  public SignedNFTAttestation(NFTAttestation nftAtt, Signature signature) {
    if (signature instanceof PersonalSignature || signature instanceof CompressedMsgSignature) {
      this.internalNftAtt = new LegacySignedNFTAttestation(nftAtt, signature);
    } else {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is not version 1 or 2, this constructor only works with version 1 or version 2"));
    }
  }

  public SignedNFTAttestation(NFTAttestation att, AsymmetricKeyParameter subjectSigningKey, int signingVersion) {
    if (signingVersion == 1 || signingVersion == 2) {
      this.internalNftAtt = new LegacySignedNFTAttestation(att, subjectSigningKey, signingVersion);
    } else if (signingVersion == 3) {
      this.internalNftAtt = new Eip712SignedNFTAttestation(att, subjectSigningKey);
    } else {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Unknown signature version"));
    }
  }

  public SignedNFTAttestation(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
    InternalSignedNFTAttestation tempAtt = constructLegacy(derEncoding, identifierAttestationVerificationKey);
    if (tempAtt != null) {
      this.internalNftAtt = tempAtt;
      return;
    }
    tempAtt = constructEip(derEncoding, identifierAttestationVerificationKey);
    if (tempAtt != null) {
      this.internalNftAtt = tempAtt;
      return;
    }
    throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not decode SignedNFTAttestation"));
  }

  private LegacySignedNFTAttestation constructLegacy(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) {
    try {
     return new LegacySignedNFTAttestation(derEncoding, identifierAttestationVerificationKey);
    } catch (IllegalArgumentException|IOException e) {
      // The NFTAttestation is not version 1
      return null;
    }
  }

  private Eip712SignedNFTAttestation constructEip(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) {
    try {
      return new Eip712SignedNFTAttestation(new String(derEncoding, StandardCharsets.UTF_8), identifierAttestationVerificationKey);
    } catch (IllegalArgumentException|IOException e) {
      // The NFTAttestation is not version 1
      return null;
    }
  }

  @Override
  public AsymmetricKeyParameter getNFTAttestationVerificationKey() {
    return internalNftAtt.getNFTAttestationVerificationKey();
  }

  @Override
  public NFTAttestation getUnsignedAttestation() {
    return internalNftAtt.getUnsignedAttestation();
  }

  @Override
  public int getSigningVersion() {
    return internalNftAtt.getSigningVersion();
  }

  @Override
  public byte[] getRawSignature() {
    return internalNftAtt.getRawSignature();
  }

  @Override
  public byte[] getDerEncoding() throws InvalidObjectException {
    return internalNftAtt.getDerEncoding();
  }

  @Override
  public boolean checkValidity() {
    return internalNftAtt.checkValidity();
  }

  @Override
  public boolean verify() {
    return internalNftAtt.verify();
  }
}
