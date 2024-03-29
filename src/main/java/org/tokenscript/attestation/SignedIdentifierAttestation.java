package org.tokenscript.attestation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.tokenscript.attestation.core.*;

import java.io.IOException;
import java.io.InvalidObjectException;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

import java.io.IOException;
import java.io.InvalidObjectException;

public class SignedIdentifierAttestation implements CheckableObject {
  private static final Logger logger = LogManager.getLogger(SignedIdentifierAttestation.class);

  private final IdentifierAttestation att;
  private final byte[] signature;
  private final AsymmetricKeyParameter attestationVerificationKey;
  private final boolean blockchainFriendly;

  public SignedIdentifierAttestation(IdentifierAttestation att, AsymmetricCipherKeyPair attestationSigningKey) {
    this(att, attestationSigningKey, Attestation.DEFAULT_BLOCKCHAIN_FRIENDLY);
  }

  public SignedIdentifierAttestation(IdentifierAttestation att, AsymmetricCipherKeyPair attestationSigningKey, boolean blockchainFriendly) {
    this.att = att;
    this.blockchainFriendly = blockchainFriendly;
    this.signature = SignatureUtility.signWithEthereum(att.getPrehash(blockchainFriendly), attestationSigningKey.getPrivate());
    this.attestationVerificationKey = attestationSigningKey.getPublic();
    constructorCheck(attestationSigningKey.getPublic());
  }

  public SignedIdentifierAttestation(byte[] derEncoding, AsymmetricKeyParameter verificationKey) throws IOException {
    try (ASN1InputStream input = new ASN1InputStream(derEncoding)) {
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
      AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
      // TODO ideally this should be refactored to SignedAttestation being augmented with an generic
      // Attestation type and an encoder to construct such an attestation
      this.att = new IdentifierAttestation(attestationEnc.getEncoded());
      this.blockchainFriendly = att.isBlockchainFriendly();
      ASN1BitString signatureEnc = ASN1BitString.getInstance(asn1.getObjectAt(2));
      this.signature = signatureEnc.getBytes();
      this.attestationVerificationKey = verificationKey;
      if (!algorithmEncoded.equals(att.getSigningAlgorithm())) {
        throw ExceptionUtil.throwException(logger,
                new IllegalArgumentException("Algorithm specified is not consistent"));
      }
      constructorCheck(verificationKey);
    }
  }

  void constructorCheck(AsymmetricKeyParameter verificationKey) {
    if (!(verificationKey instanceof ECPublicKeyParameters)) {
      throw ExceptionUtil.throwException(logger,
          new UnsupportedOperationException("Attestations must be signed with ECDSA key"));
    }
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is not valid"));
    }
  }

  public IdentifierAttestation getUnsignedAttestation() {
    return att;
  }

  public byte[] getSignature() {
    return signature;
  }

  public boolean isBlockchainFriendly() {
    return blockchainFriendly;
  }

  /**
   * Returns the public key of the attestation signer
   */
  public AsymmetricKeyParameter getAttestationVerificationKey() { return attestationVerificationKey; }

  @Override
  public byte[] getDerEncoding() {
    return constructSignedAttestation(this.att, this.signature);
  }

  private byte[] constructSignedAttestation(Attestation unsignedAtt, byte[] signature) {
    try {
      byte[] rawAtt = unsignedAtt.getPrehash(blockchainFriendly);
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawAtt));
      res.add(unsignedAtt.getSigningAlgorithm());
      res.add(new DERBitString(signature));
      return new DERSequence(res).getEncoded();
    } catch (Exception e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  @Override
  public boolean checkValidity() {
    return getUnsignedAttestation().checkValidity();
  }

  @Override
  public boolean verify() {
    try {
      if (!SignatureUtility.verifyEthereumSignature(att.getDerEncoding(blockchainFriendly), signature, attestationVerificationKey)) {
        logger.error("Could not verify signature");
        return false;
      }
    } catch (InvalidObjectException e) {
      logger.error("Could not decode the signature");
      return false;
    }
    return true;
  }

}