package org.tokenscript.attestation;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.BitSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.Attestable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

// TODO when PR 210 gets merged this should become Checkable https://github.com/TokenScript/attestation/pull/210
public class CapabilityAttestation implements Attestable {

  // TODO should be deleted when merging PR 210
  @Override
  public byte[] getCommitment() {
    return new byte[0];
  }

  public enum CapabilityType {
    READ("read"),           // 0
    WRITE("write"),         // 1
    DELEGATE("delegate");   // 2

//    private static final Map<Integer, CapabilityType> map = Map.of(
//        0, READ,
//        1, WRITE,
//        2, DELEGATE);
    private final String type;

    CapabilityType(String type) {
      this.type = type;
    }
    public String toString() {
      return type;
    }

    public static CapabilityType getType(String stringType) throws IllegalArgumentException {
      CapabilityType type;
      switch (stringType.toLowerCase()) {
        case "read":
          type = CapabilityType.READ;
          break;
        case "write":
          type = CapabilityType.WRITE;
          break;
        case "delegate":
          type = CapabilityType.DELEGATE;
          break;
        default:
          System.err.println("Could not parse capability type, must be either \"read\", \"write\" or \"delegate\"");
          throw new IllegalArgumentException("Wrong type of identifier");
      }
      return type;
    }
    public static CapabilityType getType(int index) throws IllegalArgumentException {
      CapabilityType type;
      switch (index) {
        case 0:
          type = CapabilityType.READ;
          break;
        case 1:
          type = CapabilityType.WRITE;
          break;
        case 2:
          type = CapabilityType.DELEGATE;
          break;
        default:
          System.err.println("Could not parse capability type, must be between 0 and 2");
          throw new IllegalArgumentException("Wrong type of identifier");
      }
      return type;
    }
    public static int getIndex(CapabilityType type) throws IllegalArgumentException {
      int index;
      switch (type) {
        case READ:
          index = 0;
          break;
        case WRITE:
          index = 1;
          break;
        case DELEGATE:
          index = 2;
          break;
        default:
          System.err.println("Could not parse capability type, must be either \"read\", \"write\" or \"delegate\"");
          throw new IllegalArgumentException("Wrong type of identifier");
      }
      return index;
    }
  }

  private static final Logger logger = LogManager.getLogger(CapabilityAttestation.class);

  private final BigInteger uniqueId;
  private final URL sourceDomain;
  private final URL targetDomain;
  private final Instant notBefore;
  private final Instant notAfter;
  private final Set<CapabilityType> capabilities;
  private final byte[] unsignedEncoding;
  private final byte[] signedEncoding;
  private final byte[] signature;
  private final AsymmetricKeyParameter publicKey;

  public CapabilityAttestation(BigInteger uniqueId, String sourceDomain, String targetDomain, Instant notBefore, Instant notAfter,
      Set<CapabilityType> capabilities, AsymmetricCipherKeyPair signingKeys) throws MalformedURLException {
    this.uniqueId = uniqueId;
    this.targetDomain = new URL(targetDomain);
    this.sourceDomain = new URL(sourceDomain);
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.capabilities = capabilities;
    this.publicKey = signingKeys.getPublic();

    try {
      ASN1Sequence asn1CapAtt = makeCapabilityAtt();
      this.unsignedEncoding = asn1CapAtt.getEncoded();
      this.signature = SignatureUtility.signWithEthereum(unsignedEncoding, signingKeys.getPrivate());
      this.signedEncoding = encodeSignedCapabilityAtt(asn1CapAtt);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not construct encoding", e);
    }
    constructorCheck();
  }

  public CapabilityAttestation(BigInteger uniqueId, String sourceDomain, String targetDomain, Instant notBefore, Instant notAfter,
      Set<CapabilityType> capabilities, byte[] signature, AsymmetricKeyParameter verificationKey) throws MalformedURLException {
    this.uniqueId = uniqueId;
    this.sourceDomain = new URL(sourceDomain);
    this.targetDomain = new URL(targetDomain);
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.capabilities = capabilities;
    this.signature = signature;
    this.publicKey = verificationKey;

    try {
      ASN1Sequence asn1CapAtt = makeCapabilityAtt();
      this.unsignedEncoding = asn1CapAtt.getEncoded();
      this.signedEncoding = encodeSignedCapabilityAtt(asn1CapAtt);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not construct encoding", e);
    }
    constructorCheck();
  }

  private void constructorCheck() {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify"));
    }
  }

  private ASN1Sequence makeCapabilityAtt() {
    ASN1EncodableVector capabilityAttestation = new ASN1EncodableVector();
    capabilityAttestation.add(new ASN1Integer(uniqueId));
    capabilityAttestation.add(new DERUTF8String(sourceDomain.toString()));
    capabilityAttestation.add(new DERUTF8String(targetDomain.toString()));
    capabilityAttestation.add(new ASN1Integer(notBefore.getEpochSecond()*1000));
    capabilityAttestation.add(new ASN1Integer(notAfter.getEpochSecond()*1000));
    capabilityAttestation.add(new DERBitString(convertToBitString(capabilities)));
    return new DERSequence(capabilityAttestation);
  }

  private byte[] encodeSignedCapabilityAtt(ASN1Sequence capabilityAtt) throws IOException {
    ASN1EncodableVector signedCapAtt = new ASN1EncodableVector();
    signedCapAtt.add(capabilityAtt);
    signedCapAtt.add(new DERBitString(signature));
    return new DERSequence(signedCapAtt).getEncoded();
  }

  static byte[] convertToBitString(Set<CapabilityType> capabilities) {
    BitSet set = new BitSet();
    for (CapabilityType current : capabilities) {
      set.set(CapabilityType.getIndex(current), true);
    }
    return set.toByteArray();
  }


  public BigInteger getUniqueId() {
    return uniqueId;
  }

  public String getSourceDomain() {
    return sourceDomain.toString();
  }

  public String getTargetDomain() {
    return targetDomain.toString();
  }

  public Set<CapabilityType> getCapabilities() {
    return capabilities;
  }

  /**
   * Return the capability attestation including signature
   */
  @Override
  public byte[] getDerEncoding() throws InvalidObjectException {
    return signedEncoding;
  }

  @Override
  public boolean checkValidity() {
    Timestamp timestamp = new Timestamp(notBefore.getEpochSecond()*1000);
    // It is valid the time difference between expiration and start validity
    timestamp.setValidity(notAfter.getEpochSecond()*1000-notBefore.getEpochSecond()*1000);
    if (!timestamp.validateAgainstExpiration(notAfter.getEpochSecond()*1000)) {
      logger.error("Attestation not valid at this time");
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!SignatureUtility.verifyEthereumSignature(unsignedEncoding, signature, this.publicKey)) {
      logger.error("Could not verify signature");
      return false;
    }
    return true;
  }
}
