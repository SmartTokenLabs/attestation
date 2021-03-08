package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class UseAttestation implements ASNEncodable, Verifiable, Validateable {
  private final SignedIdentityAttestation attestation;
  private final FullProofOfExponent pok;
  private final byte[] encoding;

  public UseAttestation(SignedIdentityAttestation attestation, FullProofOfExponent pok) {
    this.attestation = attestation;
    this.pok = pok;
    this.encoding = makeEncoding(attestation, pok);
  }

  public UseAttestation(byte[] derEncoding, AsymmetricKeyParameter attestationVerificationKey) {
    this.encoding = derEncoding;
    try {
      ASN1InputStream input = new ASN1InputStream(derEncoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      int i = 0;
      this.attestation = new SignedIdentityAttestation(asn1.getObjectAt(i++).toASN1Primitive().getEncoded(), attestationVerificationKey);
      this.pok = new FullProofOfExponent(asn1.getObjectAt(i++).toASN1Primitive().getEncoded());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    if (!verify()) {
      throw new IllegalArgumentException("The use attestation object is not valid");
    }
  }

  private byte[] makeEncoding(SignedIdentityAttestation attestation, FullProofOfExponent pok) {
    try {
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Sequence.getInstance(attestation.getDerEncoding()));
      res.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
      return new DERSequence(res).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public SignedIdentityAttestation getAttestation() {
    return attestation;
  }

  public ProofOfExponent getPok() {
    return pok;
  }

  @Override
  public byte[] getDerEncoding() {
    return encoding;
  }

  @Override
  public boolean verify() {
    return attestation.verify() && AttestationCrypto.verifyFullProof(pok);
  }

  @Override
  public boolean checkValidity() {
    return attestation.checkValidity();
  }
}
