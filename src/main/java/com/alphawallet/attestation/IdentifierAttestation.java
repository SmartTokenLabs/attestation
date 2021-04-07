package com.alphawallet.attestation;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class IdentifierAttestation extends Attestation implements Validateable {
  public enum AttestationType {
    PHONE,
    EMAIL
  }

  // SEE RFC 2079
  public static final ASN1ObjectIdentifier LABELED_URI = new ASN1ObjectIdentifier("1.3.6.1.4.1.250.1.57");

  /**
   * Constructs a new identifier attestation based on a secret.
   * You still need to set the optional fields, that is
   * issuer, notValidBefore, notValidAfter, smartcontracts
   */
  public IdentifierAttestation(String identity, AttestationType type, AsymmetricKeyParameter key, BigInteger secret)  {
    super();
    super.setVersion(18); // Our initial version
    super.setSubject("CN=");
    super.setSigningAlgorithm(SignatureUtility.ALGORITHM_IDENTIFIER);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setCommitment(AttestationCrypto.makeCommitment(identity, type, secret));
  }

  /**
   * Restores an attestation based on an already existing commitment
   * You still need to set the optional fields, that is
   * issuer, notValidBefore, notValidAfter, smartcontracts
   */
  public IdentifierAttestation(byte[] commitment, AsymmetricKeyParameter key)  {
    super();
    super.setVersion(18); // Our initial version
    super.setSubject("CN=");
    super.setSigningAlgorithm(SignatureUtility.ALGORITHM_IDENTIFIER);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setCommitment(commitment);
  }

  public IdentifierAttestation(String type, String identifier, AsymmetricKeyParameter key)  {
    super();
    super.setVersion(18); // Our initial version
    super.setSubject(makeLabeledURI(type, identifier));
    super.setSigningAlgorithm(SignatureUtility.ALGORITHM_IDENTIFIER);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

  }


  public IdentifierAttestation(byte[] derEncoding) throws IOException, IllegalArgumentException {
    super(derEncoding);
    if (!checkValidity()) {
      throw new IllegalArgumentException("The content is not valid for an identity attestation");
    }
  }

  private X500Name makeLabeledURI(String type, String identifier) {
    DERIA5String labelValue = new DERIA5String(identifier + " " + type);
    RDN rdn = new RDN(LABELED_URI, labelValue);
    return new X500Name(new RDN[] {rdn});
  }

  /**
   * Verifies that the the attestation is in fact a valid identity attestation, in relation to field values.
   * @return true if the field values reflect that this is a standard attestation
   */
  @Override
  public boolean checkValidity() {
    if (!super.checkValidity()) {
      return false;
    }
    if (getVersion() != 18) {
      System.err.println("The version number is " + getVersion() + ", it must be 18");
      return false;
    }
    if (!getSigningAlgorithm().equals(SignatureUtility.ALGORITHM_IDENTIFIER.getAlgorithm().getId())) {
      System.err.println("The signature algorithm is supposed to be " + SignatureUtility.ALGORITHM_IDENTIFIER.getAlgorithm().getId());
      return false;
    }
    return true;
  }

  /**
   * Set a commitment and sets it as an Attribute on the Attestation/
   * @return A proof of knowledge of the riddle
   */
  private void setCommitment(byte[] encodedRiddle) {
    ASN1EncodableVector extensions = new ASN1EncodableVector();
    extensions.add(new ASN1ObjectIdentifier(Attestation.OID_OCTETSTRING));
    extensions.add(ASN1Boolean.TRUE);
    extensions.add(new DEROctetString(encodedRiddle));
    // Double Sequence is needed to be compatible with X509V3
    this.setExtensions(new DERSequence(new DERSequence(extensions)));
  }

  @Override
  public byte[] getDerEncoding() throws InvalidObjectException {
   return super.getDerEncoding();
  }

  @Override
  public byte[] getPrehash() {
    return super.getPrehash();
  }

  @Override
  public void setVersion(int version) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }

  @Override
  public void setSigningAlgorithm(AlgorithmIdentifier oid) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }

  @Override
  public void setSubject(String subject) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }
}
