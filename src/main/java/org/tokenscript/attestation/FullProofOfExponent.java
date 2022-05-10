package org.tokenscript.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.ExceptionUtil;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;

public class FullProofOfExponent implements ProofOfExponent {
  private static final Logger logger = LogManager.getLogger(FullProofOfExponent.class);
  private final ECPoint riddle;
  private final ECPoint tPoint;
  private final BigInteger challengeResponse;
  private final byte[] unpredictableNumber;
  private final byte[] encoding;

  public FullProofOfExponent(ECPoint riddle, ECPoint tPoint, BigInteger challengeResponse, byte[] unpredictableNumber) {
    this.riddle = riddle;
    this.tPoint = tPoint;
    this.challengeResponse = challengeResponse;
    this.unpredictableNumber = unpredictableNumber;
    this.encoding = makeEncoding(riddle, tPoint, challengeResponse, unpredictableNumber);
  }

  public FullProofOfExponent(ECPoint riddle, ECPoint tPoint, BigInteger challengeResponse) {
    this(riddle, tPoint, challengeResponse, new byte[0]);
  }

  public FullProofOfExponent(byte[] derEncoded) {
    this.encoding = derEncoded;
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoded);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      input.close();
      int asn1counter = 0;
      ASN1OctetString riddleEnc = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++));
      this.riddle = AttestationCrypto.decodePoint(riddleEnc.getOctets());
      ASN1OctetString challengeEnc = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++));
      this.challengeResponse = new BigInteger(challengeEnc.getOctets());
      ASN1OctetString tPointEnc = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++));
      this.tPoint = AttestationCrypto.decodePoint(tPointEnc.getOctets());
      this.unpredictableNumber = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++)).getOctets();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
  }

  private byte[] makeEncoding(ECPoint riddle, ECPoint tPoint, BigInteger challenge, byte[] unpredictableNumber) {
    try {
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(new DEROctetString(riddle.getEncoded(false)));
      res.add(new DEROctetString(challenge.toByteArray()));
      res.add(new DEROctetString(tPoint.getEncoded(false)));
      res.add(new DEROctetString(unpredictableNumber));
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  public ECPoint getRiddle() {
    return riddle;
  }

  @Override
  public ECPoint getPoint() {
    return tPoint;
  }

  @Override
  public BigInteger getChallengeResponse() {
    return challengeResponse;
  }

  @Override
  public byte[] getUnpredictableNumber() { return unpredictableNumber; }

  public UsageProofOfExponent getUsageProofOfExponent() {
    return new UsageProofOfExponent(tPoint, challengeResponse, unpredictableNumber);
  }

  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

  /**
   * Verify that the proof is correct AND that the values contained are correct according to RFC 8235
   * The latter part is _crucial_ in preventing attacks through edge cases.
   * @return true if everything is ok
   */
  @Override
  public boolean verify() {
    try {
      // Validate that points are valid on the given curve, have correct order and are not at infinity
      AttestationCrypto.validatePointToCurve(riddle, AttestationCrypto.curve);
      AttestationCrypto.validatePointToCurve(tPoint, AttestationCrypto.curve);
      // Check the challenge response size
      if (challengeResponse.compareTo(BigInteger.ZERO) <= 0 || challengeResponse.compareTo(AttestationCrypto.curve.getOrder()) >= 0) {
        return false;
      }
      // While not strictly needed also check that points are not the generator
      if (riddle.equals(AttestationCrypto.G) || riddle.equals(AttestationCrypto.H)) {
        return false;
      }
      if (tPoint.equals(AttestationCrypto.G) || tPoint.equals(AttestationCrypto.H)) {
        return false;
      }
      return AttestationCrypto.verifyFullProof(this);
    } catch (SecurityException e) {
      return false;
    }
  }
}
