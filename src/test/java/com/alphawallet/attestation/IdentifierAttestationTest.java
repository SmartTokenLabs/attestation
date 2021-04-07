package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.core.SignatureUtility;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class IdentifierAttestationTest {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair otherKeys;
  private static SecureRandom rand;
  private static final String mail = "test@test.ts";

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testFullDecoding() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    byte[] encoding = initial.getDerEncoding();
    Attestation newAtt = new IdentifierAttestation(encoding);
    assertArrayEquals(encoding, newAtt.getPrehash());
  }

  @Test
  public void testNotStandard() throws Exception {
    Attestation initial = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic());
    byte[] encoding = initial.getPrehash();
    try {
      new IdentifierAttestation(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testCannotSet() {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, "otherTest@test.ts");
    try {
      initial.setSubject("012345678901234567890123456789012345678901234");
      fail();
    } catch (RuntimeException e) {
      // Expected
    }
    try {
      initial.setVersion(2);
      fail();
    } catch (RuntimeException e) {
      // Expected
    }
  }

  @Test
  public void testOtherSubject() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("subject");
    field.setAccessible(true);
    // Change the subject
    field.set(initial, new X500Name("CN=John Doe"));
    // Common Names are allowed
    assertTrue(initial.checkValidity());
  }

  @Test
  public void testInvalidSignature() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.TEN, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("signingAlgorithm");
    field.setAccessible(true);
    // Change the signature identifier
    field.set(initial, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.0.2.313")));
    assertFalse(initial.checkValidity());
  }

  @Test
  public void testInvalidPublicKey() throws Exception {
    IdentifierAttestation initial = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE, mail);
    Field field = initial.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    // Change the public key
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherKeys.getPublic());
    field.set(initial, spki);
    // The key is only stored one place so it is allowed to change it as long as the attestation has not been signed
    assertTrue(initial.checkValidity());
  }

}
