package com.alphawallet.attestation;

import com.alphawallet.attestation.core.AttestationCrypto;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;

public class UsageProofOfExponent implements ProofOfExponent {
  private final ECPoint tPoint;
  private final BigInteger challenge;
  private final byte[] encoding;

  public UsageProofOfExponent(ECPoint tPoint, BigInteger challenge) {
    this.tPoint = tPoint;
    this.challenge = challenge;
    this.encoding = makeEncoding(tPoint, challenge);
  }

  public UsageProofOfExponent(byte[] derEncoded) {
    this.encoding = derEncoded;
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoded);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      int asn1counter = 0;
      ASN1OctetString challengeEnc = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++));
      this.challenge = new BigInteger(challengeEnc.getOctets());
      ASN1OctetString tPointEnc = ASN1OctetString.getInstance(asn1.getObjectAt(asn1counter++));
      this.tPoint = AttestationCrypto.decodePoint(tPointEnc.getOctets());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] makeEncoding(ECPoint tPoint, BigInteger challenge) {
    try {
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(new DEROctetString(challenge.toByteArray()));
      res.add(new DEROctetString(tPoint.getEncoded(false)));
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public ECPoint getPoint() {
    return tPoint;
  }

  @Override
  public BigInteger getChallenge() {
    return challenge;
  }

  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

}
