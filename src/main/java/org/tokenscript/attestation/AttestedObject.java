package org.tokenscript.attestation;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.tokenscript.attestation.core.Attestable;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

public class AttestedObject<T extends Attestable> extends AttestedKeyObject {
  private static final Logger logger = LogManager.getLogger(AttestedObject.class);
  private final T attestableObject;
  private final SignedIdentifierAttestation att;
  private final ProofOfExponent pok;

  private final AsymmetricKeyParameter userPublicKey;

  private final byte[] encoding;

  public AttestedObject(T attestableObject, SignedIdentifierAttestation att, AsymmetricKeyParameter userPublicKey,
      BigInteger attestationSecret, BigInteger chequeSecret, AttestationCrypto crypto) {
    this(attestableObject, att, attestationSecret, chequeSecret, new byte[0], crypto);
  }

  public AttestedObject(T attestableObject, SignedIdentifierAttestation att,
      BigInteger attestationSecret, BigInteger chequeSecret, byte[] unpredictableNumber,
      AttestationCrypto crypto)
  {
    this.attestableObject = attestableObject;
    this.att = att;

    try {
      this.userPublicKey = PublicKeyFactory.createKey(att.getUnsignedAttestation().getSubjectPublicKeyInfo());
      this.pok = makeProof(attestationSecret, chequeSecret, unpredictableNumber, crypto);
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(ASN1Sequence.getInstance(this.attestableObject.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(att.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
      this.encoding = new DERSequence(vec).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    constructorCheck();
  }

  public AttestedObject(T object, SignedIdentifierAttestation att, ProofOfExponent pok) {
    this.attestableObject = object;
    this.att = att;
    this.pok = pok;

    try {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(ASN1Sequence.getInstance(object.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(att.getDerEncoding()));
      vec.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
      this.encoding = new DERSequence(vec).getEncoded();
      this.userPublicKey = PublicKeyFactory.createKey(att.getUnsignedAttestation().getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
    constructorCheck();
  }

  public AttestedObject(byte[] derEncoding, ObjectDecoder<T> attestableObjectDecoder,
                        AsymmetricKeyParameter publicAttestationSigningKey) {
    this.encoding = derEncoding;
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      input.close();
      this.attestableObject = attestableObjectDecoder.decode(asn1.getObjectAt(0).toASN1Primitive().getEncoded());
      this.att = new SignedIdentifierAttestation(asn1.getObjectAt(1).toASN1Primitive().getEncoded(), publicAttestationSigningKey);
      this.pok = new UsageProofOfExponent(asn1.getObjectAt(2).toASN1Primitive().getEncoded());
      this.userPublicKey = PublicKeyFactory.createKey(att.getUnsignedAttestation().getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    constructorCheck();
  }

  private void constructorCheck() {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify object"));
    }
  }

  public T getAttestableObject() {
    return attestableObject;
  }

  public SignedIdentifierAttestation getAtt() {
    return att;
  }

  public ProofOfExponent getPok() {
    return pok;
  }

  @Override
  public AsymmetricKeyParameter getAttestedUserKey() {
    return userPublicKey;
  }

  /**
   * Verifies that the redeem request will be accepted by the smart contract
   * @return true if the redeem request should be accepted by the smart contract
   */
  @Override
  public boolean checkValidity() {
    // CHECK: that it is an identifier attestation otherwise not all the checks of validity needed gets carried out
    try {
      byte[] attEncoded = att.getUnsignedAttestation().getDerEncoding();
      IdentifierAttestation std = new IdentifierAttestation(attEncoded);
      // CHECK: perform the needed checks of an identifier attestation
      if (!std.checkValidity()) {
        logger.error("The attestation is not a valid standard attestation");
        return false;
      }
    } catch (InvalidObjectException e) {
      logger.error("The attestation is invalid");
      return false;
    } catch (IOException e) {
      logger.error("The attestation could not be parsed as a standard attestation");
      return false;
    }

    // CHECK: that the object is still valid
    if (!getAttestableObject().checkValidity()) {
      logger.error("Object is not valid");
      return false;
    }

    // CHECK: the Ethereum address on the attestation matches receivers signing key
    String attestationEthereumAddress = getAtt().getUnsignedAttestation().getAddress();
    if (!attestationEthereumAddress.equals(SignatureUtility.addressFromKey(getAttestedUserKey()))) {
      logger.error("The attestation is not to the same Ethereum user who is sending this request");
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!attestableObject.verify()) {
      logger.error("Could not verify attestable object");
      return false;
    }
    if (!att.verify()) {
      logger.error("Could not verify attestation");
      return false;
    }
    if (!AttestationCrypto.verifyEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), pok)) {
      logger.error("Could not verify the consistency between the commitment in the attestation and the attested object");
      return false;
    }
    return true;
  }

  private UsageProofOfExponent makeProof(BigInteger attestationSecret, BigInteger objectSecret, byte[] unpredictableNumber, AttestationCrypto crypto) {
    // TODO Bob should actually verify the attestable object is valid before trying to work with on the blockchain it to avoid wasting gas
    // We require that the internal attestation is an IdentifierAttestation
    UsageProofOfExponent pok = crypto.computeEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), attestationSecret, objectSecret, unpredictableNumber);
    if (!crypto.verifyEqualityProof(att.getUnsignedAttestation().getCommitment(), attestableObject.getCommitment(), pok)) {
      throw ExceptionUtil.throwException(logger,
          new RuntimeException("The redeem proof did not verify"));
    }
    return pok;
  }

  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

  // TODO override equals and hashcode
}
