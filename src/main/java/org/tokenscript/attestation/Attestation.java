package org.tokenscript.attestation;

import com.alphawallet.token.entity.SignMessageType;
import com.alphawallet.token.entity.Signable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.Validateable;

public class Attestation implements Signable, ASNEncodable, Validateable {
  private static final Logger logger = LogManager.getLogger(Attestation.class);
  public static final ASN1ObjectIdentifier OID_OCTETSTRING = new ASN1ObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.40");
  public static final boolean DEFAULT_BLOCKCHAIN_FRIENDLY = true;

  // Attestation fields
  private ASN1Integer version = new ASN1Integer(
      18); // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
  private ASN1Integer serialNumber;

  private AlgorithmIdentifier signingAlgorithm;
  private X500Name issuer;                              // Optional
  private Date notValidBefore;                          // Optional
  private Date notValidAfter;                           // Optional
  private X500Name subject;  // CN=Ethereum address     // Optional
  private SubjectPublicKeyInfo subjectPublicKeyInfo;    // Optional
  private ASN1Sequence smartcontracts; // ASN1integers  // Optional
  private ASN1Sequence dataObject;
  private ASN1Sequence extensions;

  private final boolean blockchainFriendly;

  public Attestation() {
    blockchainFriendly = DEFAULT_BLOCKCHAIN_FRIENDLY;
  }

  public Attestation(byte[] derEncoding) throws IOException, IllegalArgumentException {
    ASN1InputStream input = new ASN1InputStream(derEncoding);
    int currentPos = 0;
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    input.close();
    ASN1TaggedObject taggedVersion = ASN1TaggedObject.getInstance(asn1.getObjectAt(currentPos));
    currentPos++;
    version = ASN1Integer.getInstance(taggedVersion.getObject());

    serialNumber = ASN1Integer.getInstance(asn1.getObjectAt(currentPos));
    currentPos++;

    signingAlgorithm = AlgorithmIdentifier.getInstance(asn1.getObjectAt(currentPos));
    currentPos++;

    ASN1Sequence issuerSeq = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos));
    currentPos++;
    // Issuer is optional in the sense that it can be an empty sequence
    if (issuerSeq.size() == 0) {
      issuer = null;
    } else {
      issuer = X500Name.getInstance(issuerSeq);
    }

    // Figure out if validity is included
    boolean expectedBlockchainFriendliness = DEFAULT_BLOCKCHAIN_FRIENDLY;
    if (asn1.getObjectAt(currentPos) instanceof ASN1Null) {
      notValidBefore = null;
      notValidAfter = null;
    } else {
      try {
        int validityCtr = 0;
        ASN1Sequence validity = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos));
        notValidBefore = ASN1GeneralizedTime.getInstance(validity.getObjectAt(validityCtr++)).getDate();
        // Check if the attestation is blockchain friendly
        Long notValidBeforeLong = null;
        try {
          notValidBeforeLong = ASN1Integer.getInstance(validity.getObjectAt(validityCtr)).longValueExact();
          validityCtr++;
          expectedBlockchainFriendliness = true;
        } catch (IllegalArgumentException e) {
          // Optional long timestamp is not included
          expectedBlockchainFriendliness = false;
        }

        if (notValidBeforeLong != null && !notValidBeforeLong.equals(notValidBefore.toInstant().getEpochSecond())) {
          logger.error("NotValidBefore integer encoding is inconsistent with the GeneralizedTime encoding");
          throw new IllegalArgumentException("NotValidBefore integer encoding is inconsistent with the GeneralizedTime encoding");
        }
        notValidAfter = ASN1GeneralizedTime.getInstance(validity.getObjectAt(validityCtr++)).getDate();
        // Check if the attestation is blockchain friendly
        Long notValidAfterLong = null;
        try {
          notValidAfterLong = ASN1Integer.getInstance(validity.getObjectAt(validityCtr)).longValueExact();
          validityCtr++;
          expectedBlockchainFriendliness = true;
        } catch (IllegalArgumentException|ArrayIndexOutOfBoundsException e) {
          // Optional long timestamp is not included
          expectedBlockchainFriendliness = false;
        }
        if (notValidAfterLong != null && !notValidAfterLong.equals(notValidAfter.toInstant().getEpochSecond())) {
          logger.error("NotValidAfter integer encoding is inconsistent with the GeneralizedTime encoding");
          throw new IllegalArgumentException("NotValidAfter integer encoding is inconsistent with the GeneralizedTime encoding");
        }
      } catch (ParseException e) {
        ExceptionUtil.throwException(logger, new IllegalArgumentException("Could not parse dates"));
      }
    }
    blockchainFriendly = expectedBlockchainFriendliness;
    currentPos++;

    ASN1Sequence subjectSeq = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos));
    currentPos++;
    // Subject is optional in the sense that it can be an empty sequence
    if (subjectSeq.size() == 0) {
      subject = null;
    } else {
      subject = X500Name.getInstance(subjectSeq);
    }

    if (asn1.getObjectAt(currentPos) instanceof ASN1Null) {
      subjectPublicKeyInfo = null;
    } else {
      subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1.getObjectAt(currentPos));
    }
    currentPos++;

    // The optional smartcontracts are included
    if (asn1.size() > currentPos && asn1.getObjectAt(currentPos) instanceof ASN1Sequence) {
      smartcontracts = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos));
      currentPos++;
    }

    if (asn1.size() > currentPos) {
      ASN1TaggedObject objects = ASN1TaggedObject.getInstance(asn1.getObjectAt(currentPos));
      currentPos++;
      if (objects.getTagNo() == 3) {
        extensions = ASN1Sequence.getInstance(objects.getObject());
      } else {
        dataObject = ASN1Sequence.getInstance(objects.getObject());
      }
    }

  }

  public int getVersion() {
    return version.getValue().intValueExact();
  }

  public void setVersion(int version) {
    this.version = new ASN1Integer(version);
  }

  public int getSerialNumber() {
    return serialNumber.getValue().intValueExact();
  }

  // TODO change to up-to 20 byte array
  public void setSerialNumber(long serialNumber) {
    this.serialNumber = new ASN1Integer(serialNumber);
  }

  public AlgorithmIdentifier getSigningAlgorithm() {
    return this.signingAlgorithm;
  }

  /**
   * The signingAlgorithm is to be used in the signature section of the attestation
   * as well as appearing in the TBS (To be signed) data
   */
  public void setSigningAlgorithm(AlgorithmIdentifier signingAlgorithm) {
    this.signingAlgorithm = signingAlgorithm;
  }

  public String getIssuer() {
    return issuer.toString();
  }

  /**
   * Constructs a name from a conventionally formatted string, such as "CN=Dave, OU=JavaSoft, O=Sun
   * Microsystems, C=US".
   */
  public void setIssuer(String issuer) {
    this.issuer = new X500Name(issuer);
  }

  public Date getNotValidBefore() {
    return notValidBefore != null ? notValidBefore : null;
  }

  public void setNotValidBefore(Date notValidBefore) {
    // Convert to milliseconds, rounded down
    Date time = new Date(notValidBefore.toInstant().getEpochSecond()*1000);
    this.notValidBefore = time;
  }

  public Date getNotValidAfter() {
    return notValidAfter != null ? notValidAfter : null;
  }

  public void setNotValidAfter(Date notValidAfter) {
    // Convert to milliseconds, rounded down
    Date time = new Date(notValidAfter.toInstant().getEpochSecond()*1000);
    this.notValidAfter = time;
  }

  public String getSubject() {
    return subject.toString();
  }

  public void setSubject(String subject) {
    this.subject = new X500Name(subject);
  }

  public void setSubject(X500Name subject) {
    this.subject = subject;
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

  public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo spki) {
    this.subjectPublicKeyInfo = spki;
  }

  public List<Long> getSmartcontracts() {
    List<Long> res = new ArrayList<>();
    Iterator<ASN1Encodable> it = smartcontracts.iterator();
    while (it.hasNext()) {
      res.add(((ASN1Integer) it.next()).getValue().longValueExact());
    }
    return res;
  }

  // TODO change to list of arrays of 20 bytes
  public void setSmartcontracts(List<Long> smartcontracts) {
    ASN1EncodableVector seq = new ASN1EncodableVector();
    for (long current : smartcontracts) {
      seq.add(new ASN1Integer(current));
    }
    this.smartcontracts = new DERSequence(seq);
  }

  public ASN1Sequence getExtensions() {
    return extensions;
  }

  public void setExtensions(ASN1Sequence extensions) {
    if (dataObject != null) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException( "DataObject already set. Only one of DataObject and Extensions is allowed."));
    }
    this.extensions = extensions;
  }

  public ASN1Sequence getDataObject() {
    return dataObject;
  }

  public void setDataObject(ASN1Sequence dataObject) {
    if (extensions != null) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException( "Extensions already set. Only one of DataObject and Extensions is allowed."));
    }
    this.dataObject = dataObject;
  }

  public boolean isBlockchainFriendly() {
    return blockchainFriendly;
  }
  /**
   * Returns true if the attestation obeys X509v3, RFC 5280
   */
  public boolean isValidX509() {
    if (version.getValue().intValueExact() != 0 && version.getValue().intValueExact() != 1
        && version.getValue().intValueExact() != 2) {
      logger.error("Incorrect version number");
      return false;
    }
    if (issuer == null || issuer.getRDNs().length == 0) {
      logger.error("Issuer info not set");
      return false;
    }
    if (notValidBefore == null || notValidAfter == null) {
      logger.error("Validity period not set");
      return false;
    }
    if (subject == null) {
      logger.error("Subject info not set");
      return false;
    }
    if (subjectPublicKeyInfo == null) {
      logger.error("No subject public key info set");
      return false;
    }
    if (smartcontracts != null) {
      logger.error("Smart contract info set");
      return false;
    }
    if (dataObject != null) {
      logger.error("Data object set");
      return false;
    }
    if (version == null || subject == null || serialNumber == null || signingAlgorithm == null) {
      logger.error("Version, serial number, subject or algorithm missing");
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    if (version == null || subject == null || serialNumber == null || signingAlgorithm == null) {
      logger.error("Version, serial number, algorithm or extension/dataObject missing");
      return false;
    }
    if (getNotValidBefore() != null && getNotValidAfter() != null) {
      Timestamp timestamp = new Timestamp(getNotValidBefore().getTime());
      // It is valid the time difference between expiration and start validity
      timestamp.setValidity(getNotValidAfter().getTime()-getNotValidBefore().getTime());
      if (!timestamp.validateAgainstExpiration(getNotValidAfter().getTime())) {
        logger.error("Attestation not valid at this time");
        return false;
      }
    }
    if (extensions != null && dataObject != null) {
      return false;
    }
    return true;
  }

  @Override
  public byte[] getDerEncoding() throws InvalidObjectException {
    return getDerEncoding(blockchainFriendly);
  }
  public byte[] getDerEncoding(boolean blockchainFriendlyEncoding) throws InvalidObjectException {
    byte[] attEncoded = getPrehash(blockchainFriendlyEncoding);
    // The method returns null if the encoding is invalid
    if (attEncoded == null) {
      throw ExceptionUtil.throwException(logger, new InvalidObjectException("The attestation is not valid"));
    }
    return attEncoded;
  }

  @Override
  public byte[] getPrehash() {
    return getPrehash(blockchainFriendly);
  }
  /**
   * Construct the DER encoded byte array to be signed. Returns null if the Attestation object is
   * not valid
   */
  public byte[] getPrehash(boolean blockchainFriendlyEncoding) {
    if (!checkValidity()) {
      logger.error("Attestation is not valid");
      return null;
    }
    ASN1EncodableVector res = new ASN1EncodableVector();
    res.add(new DERTaggedObject(true, 0, this.version));
    res.add(this.serialNumber);
    res.add(this.signingAlgorithm);
    res.add(this.issuer == null ? new DERSequence() : this.issuer);
    if (this.notValidAfter != null && this.notValidBefore != null) {
      ASN1EncodableVector date = new ASN1EncodableVector();
      date.add(new ASN1GeneralizedTime(this.notValidBefore));
      if (blockchainFriendlyEncoding) {
        date.add(new ASN1Integer(this.notValidBefore.toInstant().getEpochSecond()));
      }
      date.add(new ASN1GeneralizedTime(this.notValidAfter));
      if (blockchainFriendlyEncoding) {
        date.add(new ASN1Integer(this.notValidAfter.toInstant().getEpochSecond()));
      }
      res.add(new DERSequence(date));
    } else {
      res.add(DERNull.INSTANCE);
    }
    res.add(this.subject == null ? new DERSequence() : this.subject);
    res.add(this.subjectPublicKeyInfo == null ? DERNull.INSTANCE : this.subjectPublicKeyInfo);
    if (this.smartcontracts != null) {
      res.add(this.smartcontracts);
    }
    // The validity check ensure that only one of "extensions" and "dataObject" is set
    if (this.extensions != null) {
      res.add(new DERTaggedObject(true, 3, this.extensions));
    }
    if (this.dataObject != null) {
      res.add(new DERTaggedObject(true, 4, this.dataObject));
    }
    try {
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  @Override
  public String getOrigin() {
    logger.error("Method not implemented!");
    return null;
  }

  @Override
  public CharSequence getUserMessage() {
    logger.error("Method not implemented!");
    return null;
  }

  @Override
  public String getMessage() {
    logger.error("Method not implemented!");
    throw ExceptionUtil.throwException(logger, new RuntimeException("GetMessage is not applicable here"));
  }

  @Override
  public SignMessageType getMessageType()
  {
    return SignMessageType.ATTESTATION;
  }

  @Override
  public long getCallbackId() {
    // TODO check that dataObject is actually an Extensions
    logger.error("Method not implemented!");
    return 0;
  }
}
