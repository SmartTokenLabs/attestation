package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class HelperTest {
  public static final int CHARS_IN_LINE = 65;
  public static final AlgorithmIdentifier ECDSA_WITH_SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

//  public static KeyPair constructKeys(SecureRandom rand) throws Exception {
//    Security.addProvider(new BouncyCastleProvider());
//    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(AttestationCrypto.SIGNATURE_ALG, "BC");
//    ECGenParameterSpec ecSpec = new ECGenParameterSpec(AttestationCrypto.ECDSA_CURVE);
//    keyGen.initialize(ecSpec, rand);
//    return keyGen.generateKeyPair();
//  }

  public static IdentifierAttestation makeUnsignedStandardAtt(AsymmetricKeyParameter key,
      BigInteger secret, String mail) {
    IdentifierAttestation att = new IdentifierAttestation(mail, AttestationType.EMAIL, key, secret);
    att.setIssuer("CN=ALX");
    att.setSerialNumber(1);
    att.setSmartcontracts(Arrays.asList(42L, 1337L));
    assertTrue(att.checkValidity());
    assertFalse(att.isValidX509()); // Since the version is wrong, and algorithm is non-standard
    return att;
  }

  public static Attestation makePublicIdAttestation(AsymmetricKeyParameter key, String type, String identifier) {
    IdentifierAttestation att = new IdentifierAttestation(type, identifier, key);
    att.setIssuer("CN=ALPHAWALLET");
    att.setSerialNumber(1);
    att.setNotValidAfter(new Date(System.currentTimeMillis() + 1000L*60L*60L*24L*365L)); // Valid for 1 year
    assertTrue(att.checkValidity());
    return att;
  }

  /* the unsigned x509 attestation will have a subject of "CN=0x2042424242424564648" */
  public static Attestation makeUnsignedx509Att(AsymmetricKeyParameter key) throws IOException  {
    Attestation att = new Attestation();
    att.setVersion(2); // =v3 since counting starts from 0
    att.setSerialNumber(42);
    att.setSigningAlgorithm(ECDSA_WITH_SHA256); // ECDSA with SHA256 which is needed for a proper x509
    att.setIssuer("CN=ALX");
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(System.currentTimeMillis()+3600000)); // Valid for an hour
    att.setSubject("CN=0x2042424242424564648");
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
    att.setSubjectPublicKeyInfo(spki);
    ASN1EncodableVector extensions = new ASN1EncodableVector();
    extensions.add(new ASN1ObjectIdentifier(Attestation.OID_OCTETSTRING));
    extensions.add(ASN1Boolean.TRUE);
    extensions.add(new DEROctetString("hello world".getBytes()));
    // Double Sequence is needed to be compatible with X509V3
    att.setExtensions(new DERSequence(new DERSequence(extensions)));
    assertTrue(att.isValidX509());
    return att;
  }

  public static Attestation makeMaximalAtt(AsymmetricKeyParameter key) throws IOException {
    Attestation att = new Attestation();
    att.setVersion(18); // Our initial version
    att.setSerialNumber(42);
    att.setSigningAlgorithm(SignatureUtility.EC_PUBLIC_KEY_IDENTIFIER);
    att.setIssuer("CN=ALX");
    Date now = new Date();
    att.setNotValidBefore(now);
    att.setNotValidAfter(new Date(System.currentTimeMillis()+3600000)); // Valid for an hour
    att.setSubject("CN=0x2042424242424564648");
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
    att.setSubjectPublicKeyInfo(spki);
    att.setSmartcontracts(Arrays.asList(42L, 1337L));
    ASN1EncodableVector dataObject = new ASN1EncodableVector();
    dataObject.add(new DEROctetString("hello world".getBytes()));
    dataObject.add(new ASN1Integer(42));
    att.setDataObject(new DERSequence(dataObject));
    assertTrue(att.checkValidity());
    return att;
  }

  public static Attestation makeMinimalAtt() {
    Attestation att = new Attestation();
    att.setVersion(18); // Our initial version
    att.setSerialNumber(42);
    att.setSubject("CN=");
    att.setSigningAlgorithm(SignatureUtility.EC_PUBLIC_KEY_IDENTIFIER);
    ASN1EncodableVector dataObject = new ASN1EncodableVector();
    dataObject.add(new DEROctetString("hello world".getBytes()));
    att.setDataObject(new DERSequence(dataObject));
    assertTrue(att.checkValidity());
    return att;
  }
}
