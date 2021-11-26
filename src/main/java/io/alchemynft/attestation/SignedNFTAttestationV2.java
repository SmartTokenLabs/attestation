package io.alchemynft.attestation;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.eip712.Eip712ObjectSigner;
import org.tokenscript.attestation.eip712.Eip712ObjectValidator;
import org.tokenscript.eip712.FullEip712InternalData;

public class SignedNFTAttestationV2 implements SignedNFTAttestation {
  private static final Logger logger = LogManager.getLogger(SignedNFTAttestationV2.class);
  public static final String DEFAULT_DOMAIN = "https://autographnft.io";

  private Eip712ObjectValidator<NFTAttestation> validator;

  private final NFTAttestation att;
  private final String signature;
  private final String signedEIP712;

  public SignedNFTAttestationV2(NFTAttestation att, AsymmetricKeyParameter subjectSigningKey) {
    try {
      NFTAttestationDecoder decoder = new NFTAttestationDecoder(
          att.getSignedIdentifierAttestation().getAttestationVerificationKey());
      validator = new Eip712ObjectValidator<NFTAttestation>(decoder, new NFTAttestationEncoder(),
          DEFAULT_DOMAIN);
      Eip712ObjectSigner eipSigner = new Eip712ObjectSigner(subjectSigningKey,
          new NFTAttestationEncoder());
      this.signedEIP712 = eipSigner.buildSignedToken(att, DEFAULT_DOMAIN);
      this.att = validator.retrieveUnderlyingObject(signedEIP712);
      this.signature = eipSigner.getSignatureFromJson(signedEIP712);
    } catch (IOException e) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Could not decode underlying NFTAttestation"));
    }
    constructorCheck();
  }

  public SignedNFTAttestationV2(String signedEIP712, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
    NFTAttestationDecoder decoder = new NFTAttestationDecoder(identifierAttestationVerificationKey);
    validator = new Eip712ObjectValidator<NFTAttestation>(decoder, new NFTAttestationEncoder(), DEFAULT_DOMAIN);
    this.signedEIP712 = signedEIP712;
    this.att = validator.retrieveUnderlyingObject(signedEIP712);
    this.signature = validator.getSignatureFromJson(signedEIP712);
    constructorCheck();
  }

  private void constructorCheck() {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("The NFTAttestation is invalid"));
    }
  }

  /**
   * Returns the public key of the NFTattestation signer
   */
  public AsymmetricKeyParameter getNFTAttestationVerificationKey() {
    return validator.retrieveUserPublicKey(signedEIP712, FullEip712InternalData.class);
  }

  public String getSignedEIP712() {
    return signedEIP712;
  }

  @Override
  public NFTAttestation getUnsignedAttestation() {
    return att;
  }

  public String getSignature() {
    return signature;
  }

  /**
   * Checks the validity of the underlying NFTAttestation
   */
  @Override
  public boolean checkValidity() {
    return att.checkValidity();
  }

  /**
   * Verifies the entire EIP712 request, including domain, timestamp, usage string, signature and the
   * @return
   */
  @Override
  public boolean verify() {
    return validator.validateRequest(signedEIP712);
  }

  /**
   * Returns the ASN encoding of the underlying NFTAttestation
   */
  @Override
  public byte[] getDerEncoding() {
    return att.getDerEncoding();
  }
}
