package com.alphawallet.attestation;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Validateable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class IdentifierAttestation extends Attestation implements Validateable {
  public enum AttestationType {
    PHONE,
    EMAIL
  }

  /**
   * Constructs a new identifier attestation based on a secret.
   * You still need to set the optional fields, that is
   * issuer, notValidBefore, notValidAfter, smartcontracts
   */
  public IdentifierAttestation(String identity, AttestationType type, AsymmetricKeyParameter key, BigInteger secret)  {
    super();
    super.setVersion(18); // Our initial version
    super.setSubject("CN=" + AttestationCrypto.addressFromKey(key));
    super.setSigningAlgorithm(AttestationCrypto.OID_SIGNATURE_ALG);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setRiddle(AttestationCrypto.makeCommitment(identity, type, secret));
  }

  /**
   * Restores an attestation based on an already existing riddle
   * You still need to set the optional fields, that is
   * issuer, notValidBefore, notValidAfter, smartcontracts
   */
  public IdentifierAttestation(byte[] riddle, AsymmetricKeyParameter key)  {
    super();
    super.setVersion(18); // Our initial version
    super.setSubject("CN=" + AttestationCrypto.addressFromKey(key));
    super.setSigningAlgorithm(AttestationCrypto.OID_SIGNATURE_ALG);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      super.setSubjectPublicKeyInfo(spki);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    setRiddle(riddle);
  }


  public IdentifierAttestation(byte[] derEncoding) throws IOException, IllegalArgumentException {
    super(derEncoding);
    if (!checkValidity()) {
      throw new IllegalArgumentException("The content is not valid for an identity attestation");
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
    if (getVersion() != 18) {
      System.err.println("The version number is " + getVersion() + ", it must be 18");
      return false;
    }
    if (getSubject() == null || getSubject().length() != 45 || !getSubject()
        .startsWith("CN=0x")) { // The address is 2*20+5 chars long because it starts with CN=0x
      System.err.println("The subject is supposed to only be an Ethereum address as the Common Name");
      return false;
    }
    if (!getSigningAlgorithm().equals(AttestationCrypto.OID_SIGNATURE_ALG)) {
      System.err.println("The signature algorithm is supposed to be " + AttestationCrypto.OID_SIGNATURE_ALG);
      return false;
    }
    // Verify that the subject public key matches the subject common name
    try {
      AsymmetricKeyParameter parsedSubjectKey = PublicKeyFactory
          .createKey(getSubjectPublicKeyInfo());
      String parsedSubject = "CN=" + AttestationCrypto.addressFromKey(parsedSubjectKey);
      if (!parsedSubject.equals(getSubject())) {
        System.err.println("The subject public key does not match the Ethereum address attested to");
        return false;
      }
    } catch (IOException e) {
      System.err.println("Could not parse subject public key");
    }
    return true;
  }

  /**
   * Set a riddle and sets it as an Attribute on the Attestation/
   * @return A proof of knowledge of the riddle
   */
  private void setRiddle(byte[] encodedRiddle) {
    ASN1EncodableVector extensions = new ASN1EncodableVector();
    extensions.add(new ASN1ObjectIdentifier(Attestation.OID_OCTETSTRING));
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
  public void setSigningAlgorithm(String oid) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }

  @Override
  public void setSubject(String subject) {
    throw new RuntimeException("Not allowed to be manually set in concrete Attestation");
  }
}
