package com.alphawallet.attestation;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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

  public static final int HIDDEN_IDENTIFIER_VERSION = 18;
  public static final int NFT_VERSION = 19;
  // SEE RFC 2079
  public static final ASN1ObjectIdentifier LABELED_URI = new ASN1ObjectIdentifier("1.3.6.1.4.1.250.1.57");
  // ECDSA with recommended (for use with keccak signing since there is no explicit standard OID for this)
  public static final AlgorithmIdentifier DEFAULT_SIGNING_ALGORITHM = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.2"));


  /**
   * Constructs a new identifier attestation based on a secret, with unlimited validity by default
   * You still need to set the optional fields, that is
   * issuer, smartcontracts
   */
  public IdentifierAttestation(String identity, AttestationType type, AsymmetricKeyParameter key, BigInteger secret)  {
    super();
    super.setVersion(HIDDEN_IDENTIFIER_VERSION);
    super.setSubject("CN=");
    super.setSigningAlgorithm(DEFAULT_SIGNING_ALGORITHM);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setCommitment(AttestationCrypto.makeCommitment(identity, type, secret));
    setUnlimitedValidity();
  }

  /**
   * Restores an attestation based on an already existing commitment, with unlimited validity by default
   * You still need to set the optional fields, that is
   * issuer, smartcontracts
   */
  public IdentifierAttestation(byte[] commitment, AsymmetricKeyParameter key)  {
    super();
    super.setVersion(HIDDEN_IDENTIFIER_VERSION);
    super.setSubject("CN=");
    super.setSigningAlgorithm(DEFAULT_SIGNING_ALGORITHM);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setCommitment(commitment);
    setUnlimitedValidity();
  }

  /**
   * Constructs an attestation with *public* identifier and with unlimited validity by default
   * You still need to set the optional fields, that is
   * issuer, smartcontracts
   */
  public IdentifierAttestation(String type, String identifier, AsymmetricKeyParameter key)  {
    super();
    super.setVersion(NFT_VERSION);
    super.setSubject(makeLabeledURI(type, identifier));
    super.setSigningAlgorithm(SignatureUtility.EC_PUBLIC_KEY_IDENTIFIER);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setUnlimitedValidity();
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

  private void setUnlimitedValidity() {
    try {
      super.setNotValidBefore(new Date(Clock.systemUTC().millis()));
      SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
      // This is used to indicate unlimited validity, see https://tools.ietf.org/html/rfc5280#section-4.1.2.5
      Date notValidAfter = dateFormat.parse("99991231235959Z");
      super.setNotValidAfter(notValidAfter);
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
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
    if (getVersion() != HIDDEN_IDENTIFIER_VERSION && getVersion() != NFT_VERSION) {
      System.err.println("The version number is " + getVersion() + ", it must be " + HIDDEN_IDENTIFIER_VERSION + " or " + NFT_VERSION);
      return false;
    }
    if (!getSigningAlgorithm().equals(SignatureUtility.EC_PUBLIC_KEY_IDENTIFIER.getAlgorithm().getId())) {
      System.err.println("The signature algorithm is supposed to be " + SignatureUtility.EC_PUBLIC_KEY_IDENTIFIER
          .getAlgorithm().getId());
      return false;
    }
    if (getVersion() == NFT_VERSION) {
      String subject = getSubject();
      if (!subject.contains(LABELED_URI.getId())) {
        return false;
      }
    }
    if (getVersion() == HIDDEN_IDENTIFIER_VERSION) {
      try {
        // Check that the first extension is an octet-string, i.e. a commitment
        ASN1Sequence firstExtension = ((ASN1Sequence) getExtensions().toArray()[0]);
        ASN1ObjectIdentifier firstExtensionIdentifier = (ASN1ObjectIdentifier) firstExtension
            .getObjectAt(0).toASN1Primitive();
        if (!firstExtensionIdentifier.equals(Attestation.OID_OCTETSTRING)) {
          return false;
        }
      } catch (Exception e) {

    /*if (getSubject() == null || !getSubject().startsWith("CN=") || !ValidationTools.isAddress(getSubject().substring(3))) {
      System.err.println("The subject is supposed to only be an Ethereum address as the Common Name");
      return false;
    }
    // Verify that the subject public key matches the subject common name
    try {
      AsymmetricKeyParameter parsedSubjectKey = PublicKeyFactory
          .createKey(getSubjectPublicKeyInfo());
      String parsedSubject = "CN=" + SignatureUtility.addressFromKey(parsedSubjectKey);
      if (!parsedSubject.equals(getSubject())) {
        System.err.println("The subject public key does not match the Ethereum address attested to");*/

        return false;
      }
    }
    return true;
  }

  public byte[] getCommitment() {
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    ASN1Sequence extensions = DERSequence.getInstance(getExtensions().getObjectAt(0));
    // Index in the second DER sequence is 2 since the third object in an extension is the actual value
    return ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
  }

  public String getAddress() {
    // Remove the "CN=" prefix
    return getSubject().substring(3);
  }

  /**
   * Set a commitment and sets it as an Attribute on the Attestation/
   * @return A proof of knowledge of the riddle
   */
  private void setCommitment(byte[] encodedRiddle) {
    ASN1EncodableVector extensions = new ASN1EncodableVector();
    extensions.add(Attestation.OID_OCTETSTRING);
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
  public void setSubject(String subject) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }
}
