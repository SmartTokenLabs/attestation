package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.apache.logging.log4j.core.util.Assert;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestRedeemCheque {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair issuerKeys;
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    AttestationCrypto crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
    issuerKeys = crypto.constructECKeys();
    senderKeys = crypto.constructECKeys();
  }

  @Test
  public void testSunshine() {
    BigInteger subjectSecret = new BigInteger("42");
    BigInteger senderSecret = new BigInteger("112");
    Attestation att = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret);
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    assertTrue(signed.verify());
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    assertTrue(cheque.verify());
    assertTrue(cheque.checkValidity());
    RedeemCheque redeem = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret, senderSecret);
    assertTrue(redeem.verify());
    assertTrue(redeem.checkValidity());
    // *** PRINT DER ENCODING OF OBJECTS ***
    try {
      PublicKey pk;
      System.out.println("Signed attestation:");
      System.out.println(DERUtility.printDER(signed.getDerEncoding(), "SIGNABLE"));
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(issuerKeys.getPublic()));
      System.out.println("Attestation verification key:");
      System.out.println(DERUtility.printDER(pk.getEncoded(),"PUBLIC KEY"));

      System.out.println("Cheque:");
      System.out.println(DERUtility.printDER(cheque.getDerEncoding(), "CHEQUE"));
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
    BigInteger subjectSecret = new BigInteger("42424242");
    BigInteger senderSecret = new BigInteger("112112112");
    Attestation att = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), subjectSecret);
    SignedAttestation signed = new SignedAttestation(att, issuerKeys);
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    RedeemCheque redeem = new RedeemCheque(cheque, signed, subjectKeys, subjectSecret, senderSecret);
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
}
