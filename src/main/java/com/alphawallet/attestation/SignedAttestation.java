package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.io.InvalidObjectException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SignedAttestation implements ASNEncodable, Verifiable, Validateable {
  private final Attestation att;
  private final byte[] signature;
  private final AsymmetricKeyParameter attestationVerificationKey;

  public SignedAttestation(Attestation att, AsymmetricCipherKeyPair attestationSigningkey) {
    this.att = att;
    this.signature = SignatureUtility.signDeterministic(att.getPrehash(), attestationSigningkey.getPrivate());
    this.attestationVerificationKey = attestationSigningkey.getPublic();
    if (!verify()) {
      throw new IllegalArgumentException("The signature is not valid");
    }
  }

  public SignedAttestation(byte[] derEncoding, AsymmetricKeyParameter signingPublicKey) throws IOException {
    ASN1InputStream input = new ASN1InputStream(derEncoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    this.att = new Attestation(attestationEnc.getEncoded());
    DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(2));
    this.signature = signatureEnc.getBytes();
    this.attestationVerificationKey = signingPublicKey;
    if (!verify()) {
      throw new IllegalArgumentException("The signature is not valid");
    }
  }

  public Attestation getUnsignedAttestation() {
    return att;
  }

  public byte[] getSignature() {
    return signature;
  }

  /**
   * Returns the public key of the attestation signer
   */
  public AsymmetricKeyParameter getAttestationVerificationKey() { return attestationVerificationKey; }

  @Override
  public byte[] getDerEncoding() {
    return constructSignedAttestation(this.att, this.signature);
  }

  static byte[] constructSignedAttestation(Attestation unsignedAtt, byte[] signature) {
    try {
      byte[] rawAtt = unsignedAtt.getPrehash();
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawAtt));
      res.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(unsignedAtt.getSigningAlgorithm())));
      res.add(new DERBitString(signature));
      return new DERSequence(res).getEncoded();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean checkValidity() {
    return getUnsignedAttestation().checkValidity();
  }

  @Override
  public boolean verify() {
    try {
      return SignatureUtility.verify(att.getDerEncoding(), signature, attestationVerificationKey);
    } catch (InvalidObjectException e) {
      return false;
    }
  }


}