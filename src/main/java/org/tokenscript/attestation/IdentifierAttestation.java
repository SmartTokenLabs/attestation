package org.tokenscript.attestation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.tokenscript.attestation.core.*;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;

import static org.tokenscript.attestation.core.AttestationCrypto.BYTES_IN_DIGEST;

public class IdentifierAttestation extends Attestation implements Validateable {
  public enum AttestationType {
    PHONE ("phone"),
    EMAIL ("email"),
    INETPERSONA("inetpersona");

    private final String type;

    AttestationType(String type) {
      this.type = type;
    }

    public boolean equals(String otherType) {
      return type.equals(otherType);
    }

    public String toString() {
      return this.type;
    }

    public static AttestationType getType(String stringType) throws IllegalArgumentException {
      AttestationType type;
      switch (stringType.toLowerCase()) {
        case "mail":
        case "email":
          type = AttestationType.EMAIL;
          break;
        case "phone":
          type = AttestationType.PHONE;
          break;
        case "inetpersona":
          type = AttestationType.INETPERSONA;
          break;
        default:
          System.err.println("Could not parse identifier type, must be either \"mail\", \"phone\" or \"InetPersona\"");
          throw new IllegalArgumentException("Wrong type of identifier");
      }
      return type;
    }
  }

  private static final Logger logger = LogManager.getLogger(IdentifierAttestation.class);
  public static final int HIDDEN_IDENTIFIER_VERSION = 18;
  public static final int NFT_VERSION = 19;
  public static final String HIDDEN_TYPE = "HiddenType";
  public static final String HIDDEN_IDENTIFIER = "HiddenIdentifier";

  // SEE RFC 2079
  public static final ASN1ObjectIdentifier LABELED_URI = new ASN1ObjectIdentifier("1.3.6.1.4.1.250.1.57");

  private final String identifier;
  private final String type;


  /**
   * Constructs a new identifier attestation based on a secret, with unlimited validity by default
   * You still need to set the optional fields, that is
   * issuer, smartcontracts
   */
  public IdentifierAttestation(String identifier, AttestationType type, AsymmetricKeyParameter key, BigInteger secret)  {
    super();
    super.setVersion(HIDDEN_IDENTIFIER_VERSION);
    super.setSubject("CN=");
    super.setSigningAlgorithm(SignatureUtility.ECDSA_OID);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    setCommitment(AttestationCrypto.makeCommitment(identifier, type, secret));
    setUnlimitedValidity();

    this.identifier = identifier;
    this.type = type.toString();
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
    super.setSigningAlgorithm(SignatureUtility.ECDSA_OID);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    setCommitment(commitment);
    setUnlimitedValidity();
    this.type = HIDDEN_TYPE;
    this.identifier = HIDDEN_IDENTIFIER;

  }

  /**
   * Constructs an attestation with *public* identifier and with unlimited validity by default
   * You still need to set the optional fields, that is
   * issuer, smartcontracts.
   * This is done using labeledURL, hence URL must be a valid URL
   */
  public IdentifierAttestation(String label, String URL, AsymmetricKeyParameter subjectKey) throws MalformedURLException {
    super();
    super.setVersion(NFT_VERSION);
    super.setSubject(makeLabeledURI(label, URL));
    super.setSigningAlgorithm(SignatureUtility.ECDSA_OID);
    super.setIssuer("CN=attestation.id");
    super.setSerialNumber(1);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKey);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
    setUnlimitedValidity();
    this.type = label;
    this.identifier = URL;

  }

  public IdentifierAttestation(byte[] derEncoding) throws IOException, IllegalArgumentException {
    super(derEncoding);
    if (!checkValidity()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not validate object"));
    }
    if (getVersion() == NFT_VERSION) {
      RDN[] labeledURIRDN = (new X500Name(getSubject())).getRDNs(LABELED_URI);
      DERUTF8String labeledURI = (DERUTF8String) labeledURIRDN[0].getFirst().getValue();
      String[] typeAndIdentifier = URLDecoder.decode(labeledURI.getString()).split(" ");
      this.type = typeAndIdentifier[0];
      this.identifier = typeAndIdentifier[1];
    } else {
      this.type = HIDDEN_TYPE;
      this.identifier = HIDDEN_IDENTIFIER;
    }
  }

  /**
   * @param label the label of the URL, similar to what is inside <a>...</a>
   * @param URL the URL itself, similar to what is in <a href="...">, note that
   * it should already be URLencoded therefore not containing space
   */
  private X500Name makeLabeledURI(String label, String URL)  {
    DERUTF8String labeledURLValue = new DERUTF8String(URL + " " + label);
    RDN rdn = new RDN(LABELED_URI, labeledURLValue);
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
      throw ExceptionUtil.makeRuntimeException(logger, "Could not parse date", e);
    }
  }

  /**
   * Verifies that the the attestation is in fact a valid identifier attestation, in relation to field values.
   * @return true if the field values reflect that this is a standard attestation
   */
  @Override
  public boolean checkValidity() {
    if (!super.checkValidity()) {
      logger.error("Could not check validity of the underlying attestation");
      return false;
    }
    if (getVersion() != HIDDEN_IDENTIFIER_VERSION && getVersion() != NFT_VERSION) {
      logger.error("The version number is " + getVersion() + ", it must be either " + HIDDEN_IDENTIFIER_VERSION + " or " + NFT_VERSION);
      return false;
    }
    if (!getSigningAlgorithm().equals(SignatureUtility.ECDSA_OID)) {
      logger.error("The subject is supposed to only be an Ethereum address as the Common Name");
      return false;
    }
    if (getVersion() == NFT_VERSION) {
      String subject = getSubject();
      if (!subject.contains(LABELED_URI.getId())) {
        logger.error("A NFT Identifier attestation must have a labeled uri as subject");
        return false;
      }
    }
    if (getVersion() == HIDDEN_IDENTIFIER_VERSION) {
      // Ensure that there is a commitment as part of the attestation
      try {
        if (getCommitment().length < BYTES_IN_DIGEST) {
          logger.error("The attestation does not contain a valid commitment");
          return false;
        }
      } catch (Exception e) {
        logger.error("It was not possible to decode the attestation commitment");
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
    try {
      return SignatureUtility.addressFromKey(PublicKeyFactory.createKey(getSubjectPublicKeyInfo()));
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode the address", e);
    }
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

  public String getAsUrlWithIdentifier() {
    String encodedIdentifier = URLEncoder.encode(this.identifier, StandardCharsets.UTF_8);
    String encodedType = URLEncoder.encode(this.type, StandardCharsets.UTF_8);
    return getAsUrlWithoutIdentifier() + "&" + encodedType + "=" + encodedIdentifier;
  }

  public String getAsUrlWithoutIdentifier() {
    try {
      return URLUtility.encodeData(getDerEncoding());
    } catch (InvalidObjectException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not get DER encoding", e);
    }
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
    throw ExceptionUtil.throwException(logger,
        new RuntimeException("Not allowed to be manually set in concrete Attestation"));
  }

  @Override
  public void setSubject(String subject) {
    throw ExceptionUtil.throwException(logger,
        new RuntimeException("Not allowed to be manually set in concrete Attestation"));
  }
}
