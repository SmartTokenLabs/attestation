package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.io.InvalidObjectException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class SignedIdentityAttestation implements ASNEncodable, Verifiable, Validateable {
  private final IdentifierAttestation att;
  private final byte[] signature;
  private final AsymmetricKeyParameter attestationVerificationKey;

  public SignedIdentityAttestation(IdentifierAttestation att, AsymmetricCipherKeyPair attestationSigningKey) {
    this.att = att;
    this.attestationVerificationKey = attestationSigningKey.getPublic();
    try {
      AlgorithmIdentifier algorithmIdentifier = SubjectPublicKeyInfoFactory
          .createSubjectPublicKeyInfo(attestationVerificationKey).getAlgorithm();
      // Ensure that the signing algorithm is correct
      this.att.setSigningAlgorithm(algorithmIdentifier);
    } catch (IOException e) {
      throw new IllegalArgumentException("Could not parse attestation and key information");
    }
    this.signature = SignatureUtility.signDeterministic(att.getPrehash(), attestationSigningKey.getPrivate());
    constructorCheck();
  }

  public SignedIdentityAttestation(byte[] derEncoding, AsymmetricKeyParameter verificationKey) throws IOException {
    ASN1InputStream input = new ASN1InputStream(derEncoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
    // TODO ideally this should be refactored to SignedAttestation being augmented with an generic
    // Attestation type and an encoder to construct such an attestation
    this.att = new IdentifierAttestation(attestationEnc.getEncoded());
    DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(2));
    this.signature = signatureEnc.getBytes();
    this.attestationVerificationKey = verificationKey;
    AlgorithmIdentifier verificationKeyIdentifier = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(verificationKey).getAlgorithm();
    if (!algorithmEncoded.equals(verificationKeyIdentifier) || !algorithmEncoded.equals(att.getSigningAlgorithm())) {
      throw new IllegalArgumentException("Algorithm specified is not consistent with keys.");
    }
    constructorCheck();
  }

  void constructorCheck() {
    if (!verify()) {
      throw new IllegalArgumentException("The signature is not valid");
    }
  }

  public IdentifierAttestation getUnsignedAttestation() {
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

  static byte[] constructSignedAttestation(IdentifierAttestation unsignedAtt, byte[] signature) {
    try {
      byte[] rawAtt = unsignedAtt.getPrehash();
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawAtt));
      res.add(unsignedAtt.getSigningAlgorithm());
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