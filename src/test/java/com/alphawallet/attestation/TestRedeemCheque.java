package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.bouncycastle.jce.ECPointUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestRedeemCheque {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair issuerKeys;
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;
  private RedeemCheque redeem;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    AttestationCrypto crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
    issuerKeys = crypto.constructECKeys();
    senderKeys = crypto.constructECKeys();
  }

  @BeforeEach
  public void makeRedeem() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    Attestation att = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret);
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    redeem = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret, senderSecret);
    assertTrue(redeem.verify());
    assertTrue(redeem.checkValidity());
  }

  @Test
  public void testSunshine() {
        // *** PRINT DER ENCODING OF OBJECTS ***
    try {
      PublicKey pk;
      System.out.println("Signed attestation:");
      System.out.println(DERUtility.printDER(redeem.getAtt().getDerEncoding(), "SIGNABLE"));
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuerKeys.getPublic()));
      System.out.println("Attestation verification key:");
      System.out.println(DERUtility.printDER(pk.getEncoded(),"PUBLIC KEY"));

      System.out.println("Cheque:");
      System.out.println(DERUtility.printDER(redeem.getCheque().getDerEncoding(), "CHEQUE"));
      System.out.println("Signed cheque verification key:");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic()));
      System.out.println(DERUtility.printDER(pk.getEncoded(),"PUBLIC KEY"));

      System.out.println("Redeem Cheque:");
      System.out.println(DERUtility.printDER(redeem.getDerEncoding(), "REDEEM"));
      System.out.println("Signed user public key (for redeem verification):");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic()));
      System.out.println(DERUtility.printDER(pk.getEncoded(),"PUBLIC KEY"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testDecoding() {
    RedeemCheque newRedeem = new RedeemCheque(redeem.getDerEncoding(), issuerKeys.getPublic(),
        subjectKeys.getPublic());
    assertTrue(newRedeem.getCheque().verify());
    assertTrue(newRedeem.getAtt().verify());
    assertTrue(newRedeem.getPok().verify());

    assertArrayEquals(redeem.getCheque().getDerEncoding(), newRedeem.getCheque().getDerEncoding());
    assertArrayEquals(redeem.getAtt().getDerEncoding(), newRedeem.getAtt().getDerEncoding());
    assertArrayEquals(redeem.getPok().getDerEncoding(), newRedeem.getPok().getDerEncoding());
    assertArrayEquals(redeem.getSignature(), newRedeem.getSignature());
    assertEquals(redeem.getUserPublicKey(), subjectKeys.getPublic());
    assertArrayEquals(redeem.getDerEncoding(), redeem.getDerEncoding());

    RedeemCheque newConstructor = new RedeemCheque(redeem.getCheque(), redeem.getAtt(), redeem.getPok(),
        redeem.getSignature(), issuerKeys.getPublic(), subjectKeys.getPublic());

    assertArrayEquals(redeem.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void testNegativeAttestation() throws Exception {
    Attestation att = redeem.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("version");
    field.setAccessible(true);
    // Invalid version for Identity Attestation along with failing signature
    field.set(att, new ASN1Integer(19));
    // Only correctly formed Identity Attestations are allowed
    assertFalse(att.checkValidity());
    assertFalse(redeem.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(redeem.getAtt().verify());
    assertFalse(redeem.verify());
  }

  @Test
  public void testNegativeCheque() throws Exception {
    Cheque cheque = redeem.getCheque();
    Field field = cheque.getClass().getDeclaredField("notValidAfter");
    field.setAccessible(true);
    // Set validity to the past
    field.set(cheque, System.currentTimeMillis()-1000);
    assertFalse(cheque.checkValidity());
    assertFalse(redeem.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(cheque.verify());
    assertFalse(redeem.verify());
  }

  // Test that the key used to sign the RedeemCheque is the same as attested to
  @Test
  public void testNegativeUnmatchingKeys() throws Exception {
    Attestation att = redeem.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuerKeys.getPublic());
    assertFalse(Arrays.equals(spki.getEncoded(), att.getSubjectPublicKeyInfo().getEncoded()));
    // Change public key
    field.set(att, spki);
    // Validation should not fail
    assertFalse(redeem.getAtt().checkValidity());
    assertFalse(redeem.checkValidity());
    // Verification should fail
    assertFalse(redeem.getAtt().verify());
    assertFalse(redeem.verify());
  }

  @Test
  public void testNegativeDifferentKeys() throws Exception {
    SignedAttestation att = redeem.getAtt();
    Field field = att.getClass().getDeclaredField("publicKey");
    field.setAccessible(true);
    // Change public key
    field.set(att, subjectKeys.getPublic());
    // Verification should fail
    assertFalse(att.verify());
    assertFalse(redeem.verify());
  }

  @Test
  public void testNegativeWrongProofIdentity() throws Exception {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());
    // Add an extra "t" in the mail address
    ProofOfExponent newPok = crypto.constructProof("testt@test.ts", AttestationType.EMAIL, new BigInteger("42424242"));
    Field field = redeem.getClass().getDeclaredField("pok");
    field.setAccessible(true);
    // Change the base point
    field.set(redeem, newPok);
    // Validation should fail
    assertFalse(redeem.checkValidity());
    // Verification should not fail
    assertTrue(newPok.verify());
    assertTrue(redeem.verify());
  }

  @Test
  public void testNegativeWrongRiddle() throws Exception {
    BigInteger secret =  new BigInteger("42424242");
    Cheque newCheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, secret);
    assertTrue(newCheque.checkValidity());
    assertTrue(newCheque.verify());
    Field field = redeem.getClass().getDeclaredField("cheque");
    field.setAccessible(true);
    // Set validity to the past
    field.set(redeem, newCheque);
    // Validation should fail since the cheque construction is randomized
    assertFalse(redeem.checkValidity());
    // Verification should not fail
    assertTrue(redeem.verify());
  }

  @Test
  public void testNegativeConstruction() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    Attestation att = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret);
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    // Add an extra t in the mail
    Cheque cheque = new Cheque("testt@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    try {
      RedeemCheque current = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret, senderSecret);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong email
    }
  }

  @Test
  public void testNegativeConstruction2() {
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    Attestation att = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret);
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    try {
      // Wrong subject secret
      RedeemCheque current = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret.add(BigInteger.ONE), senderSecret);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Wrong sender secret
      RedeemCheque current = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret, senderSecret.add(BigInteger.ONE));
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Correlated secrets
      RedeemCheque current = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret.add(BigInteger.ONE), senderSecret.add(BigInteger.ONE));
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
  }
}
