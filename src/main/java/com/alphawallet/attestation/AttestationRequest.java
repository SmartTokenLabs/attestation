package com.alphawallet.attestation;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class AttestationRequest implements ASNEncodable, Verifiable {
  private final AttestationType type;
  private final FullProofOfExponent pok;

  private final AsymmetricKeyParameter publicKey;

  public AttestationRequest(AttestationType type, FullProofOfExponent pok,
      AsymmetricKeyParameter publicKey) {
    this.type = type;
    this.pok = pok;
    this.publicKey = publicKey;

    if (!verify()) {
      throw new IllegalArgumentException("Could not verify the proof");
    }
  }

  public AttestationRequest(byte[] derEncoding) {
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      int i = 0;
      ASN1Sequence unsigned = ASN1Sequence.getInstance(asn1.getObjectAt(0));
      this.type = AttestationType.values()[
          ASN1Integer.getInstance(unsigned.getObjectAt(i++)).getValue().intValueExact()];
      this.pok = new FullProofOfExponent(
          ASN1Sequence.getInstance(unsigned.getObjectAt(i++)).getEncoded());
      this.publicKey = PublicKeyFactory
          .createKey(SubjectPublicKeyInfo.getInstance(asn1.getObjectAt(1)));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("The signature is not valid");
    }
  }

  public AttestationType getType() { return type; }

  public FullProofOfExponent getPok() { return pok; }

  public AsymmetricKeyParameter getPublicKey() { return publicKey; }

  private byte[] getUnsignedEncoding() {
    try {
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(new ASN1Integer(type.ordinal()));
      res.add(ASN1Primitive.fromByteArray(pok.getDerEncoding()));
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] getDerEncoding() {
    try {
      byte[] rawData = getUnsignedEncoding();
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawData));
      res.add(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
      return new DERSequence(res).getEncoded();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify() {
    if (!AttestationCrypto.verifyAttestationRequestProof(pok)) {
      return false;
    }
    return true;
  }
}
